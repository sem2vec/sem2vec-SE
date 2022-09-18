import logging

import angr
import claripy
import cle
from config import args, VERSION


log = logging.getLogger('SMP')
log.setLevel('WARNING')
# log.setLevel('DEBUG')


def load_proj(file_name: str, auto_load_libs=False, analysis_mode='symbolic') -> angr.Project:
    if file_name.endswith('.o'):
        # objfile, load with cle first
        o = cle.loader.Loader(file_name, auto_load_libs=auto_load_libs)
        return angr.Project(o, default_analysis_mode=analysis_mode)
    return angr.Project(file_name, auto_load_libs=auto_load_libs, default_analysis_mode=analysis_mode)


def get_offset(p: angr.Project):
    if p.loader.main_object.pic:
        return p.loader.main_object.min_addr
    else:
        return 0


def get_addr_label(addr, mode):
    return mode + ("%x" % addr)


def get_cfg(project: angr.Project):
    return project.analyses.CFGFast()


def get_block_last_insn(basic_block):
    return basic_block.capstone.insns[-1].insn


def get_insn_str(insn):
    return "0x%x\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str)


def get_following_basic_block_addr(basic_block):
    return basic_block.addr + basic_block.size


def XOR(A: list, B: list):
    C = claripy.And(claripy.And(*A), claripy.Not(claripy.And(*B)))
    D = claripy.And(claripy.And(*B), claripy.Not(claripy.And(*A)))
    return claripy.Or(C, D)


def get_expression_input(expr, with_extract=True):
    stack = [expr]
    read_from = set()
    while len(stack) > 0:
        e = stack.pop()
        if isinstance(e, claripy.ast.base.Base) and e.depth == 1 and e.symbolic:
            read_from.add(e)
        elif hasattr(e, 'args') and hasattr(e, 'depth') and e.depth > 1:
            if with_extract and e.depth == 2 and e.op == 'Extract' and e.symbolic:
                read_from.add(e)
            else:
                for arg in e.args:
                    stack.append(arg)
    return read_from


def remove_extract(vars):
    new_vars = set()
    for var in vars:
        if var.depth == 2 and var.op == 'Extract' and var.symbolic:
            for arg in var.args:
                if isinstance(arg, int):
                    continue
                if hasattr(arg, 'symbolic') and arg.symbolic:
                    new_vars.add(arg)
        else:
            new_vars.add(var)
    return new_vars


def angr_symbolic_name(symbolic_bv):
    # the encoded name should be byte array
    angr_name = str(symbolic_bv._encoded_name, encoding='utf8')
    # for registers, we only preserve the name of this register
    if angr_name.startswith('reg_'):
        return angr_name.split('_')[1]
    # for others such as memory, we simply return the encoded name
    else:
        return angr_name


def merge_fe_formulas(fc_list: list, ptr_size=64):
    """
    :param fc_list: [(formula, constraints)], the constraints is also a list
    :param ptr_size: for the last branch, there could be no formulas, we add a constant
    :return: merged formulas, and the constraints
    """
    value_dict = dict()
    all_constraints = []

    # a helper function
    def _replace_symbolic_variable(f, recursion_depth):
        if not (hasattr(f, 'depth') and hasattr(f, 'args')):
            return f
        if f.depth == 1 and f.op == 'BVS':
            val_name = f._encoded_name.decode('utf8')
            if val_name in value_dict.keys():
                return f
            # the name of a BVS is always "[name]_id_bits"
            val_name_prefix = val_name[:val_name[:val_name.rfind('_')].rfind('_')]
            for k in value_dict.keys():
                if k.startswith(val_name_prefix):
                    # find and replace f with it
                    return value_dict[k]
            # the name of a BVS is not in dictionary
            value_dict[val_name] = f
            return f
        elif f.depth > 1:
            new_args = [_replace_symbolic_variable(arg, recursion_depth + 1) for arg in f.args]
            f.args = tuple(new_args)
        return f

    # a helper function
    def _create_a_formula_branch(fc_list, idx, ptr_size):
        if idx >= len(fc_list):
            # here we return a constant
            return claripy.BVV(0xfff777, ptr_size)
        formula, constraints = fc_list[idx]
        _replace_symbolic_variable(formula, 0)
        for i in range(len(constraints)):
            _replace_symbolic_variable(constraints[i], 0)
        all_constraints.append(claripy.And(*constraints))
        if constraints:
            return claripy.If(claripy.And(*constraints),  # constraints
                              formula,  # if branch
                              _create_a_formula_branch(fc_list, idx + 1, ptr_size))  # else branch
        else:
            # empty constraint is equivalent to True
            return formula

    if fc_list:
        return _create_a_formula_branch(fc_list, 0, ptr_size), all_constraints
    return None, all_constraints


def is_assigning_value(expr):
    if isinstance(expr, claripy.ast.base.Base):
        if expr.depth == 1 and expr.symbolic:
            return True
        elif expr.depth == 2 and expr.op == 'Extract':
            return True
    return False


def is_call_instr(instr):
    return 'call' in instr.mnemonic


def is_ret_instr(instr):
    return 'ret' in instr.mnemonic


def has_section(p: angr.Project, sec_name):
    return sec_name in p.loader.main_object.sections_map.keys()


def get_section(p: angr.Project, sec_name):
    return p.loader.main_object.sections_map[sec_name]


def get_text_section(p: angr.Project):
    return get_section(p, '.text')


def get_section_range(p: angr.Project, sec_name):
    sec = get_section(p, sec_name)
    return range(sec.min_addr, sec.max_addr)


def _get_ranges(p: angr.Project, feature):
    ranges = []
    for sec_name, sec in p.loader.main_object.sections_map.items():
        if getattr(sec, feature):
            ranges.append(range(sec.min_addr, sec.max_addr))
    # we sort the ranges in this way so that the times for checking a pointer is likely to be accelerated.
    ranges = sorted(ranges, key=len)
    ranges.reverse()
    return ranges


def get_executable_ranges(p: angr.Project):
    return _get_ranges(p, 'is_executable')


def get_writable_ranges(p: angr.Project):
    return _get_ranges(p, 'is_writable')


def get_readable_ranges(p: angr.Project):
    return _get_ranges(p, 'is_readable')


def get_data_ranges(p: angr.Project):
    # executable sections are also readable sections
    # use a simple method to check
    data_ranges = []
    for sec_name, sec in p.loader.main_object.sections_map.items():
        # if not sec.is_executable and (sec.is_writable or sec.is_readable):
        if '.bss' == sec_name:
            # bss is special, the __bss_start is not in the range of bss
            data_ranges.append(range(sec.vaddr, sec.max_addr))
        elif 'data' in sec_name or (sec.is_writable and not sec.is_executable):
            data_ranges.append(range(sec.min_addr, sec.max_addr))
    data_ranges = sorted(data_ranges, key=len)
    data_ranges.reverse()
    return data_ranges


def get_obj_ranges(p: angr.Project):
    obj_ranges = []
    for obj in p.loader.all_objects:
        if obj == p.loader.main_object:
            continue
        obj_ranges.append(range(obj.min_addr, obj.max_addr))
    return obj_ranges


def in_ranges(addr, ranges: list):
    for r in ranges:
        if addr in r:
            return True
    return False


def jaccard_similarity(x: set, y: set):
    if len(x) + len(y) == 0:
        return 0.0
    return len(x.intersection(y)) / len(x.union(y))


def filter_libcall(all_func_map: dict):
    libcalls = dict()
    for f_addr, f_name in all_func_map.items():
        if f_name.startswith('.'):
            libcalls[f_addr] = f_name
    return libcalls


def get_proj_external_functions_symbols(p: angr.Project):
    extern_symbols = dict()
    for sym in p.loader.symbols:
        if sym.is_extern:
            # offset = sym.owner.min_addr
            f_addr = sym.owner.min_addr + sym.relative_addr
            extern_symbols[f_addr] = sym.name
    return extern_symbols


def get_IRSBs_path(bin_path):
    return bin_path + '.IRSBs'


def get_IRSBs_pkl_path(bin_path):
    return bin_path + '.IRSBs.pkl'


def get_insns_pkl(bin_path):
    return bin_path + '.insns.pkl'


def get_func_traces_pkl(bin_path):
    return bin_path + '.func_traces.pkl'


def get_angr_pkl_path(bin_path):
    return bin_path + "." + args.angrdir
