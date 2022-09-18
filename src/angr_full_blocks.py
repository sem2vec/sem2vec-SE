import time

import angr
import pickle
import os
import sys
from multiprocessing import Pool

import claripy.bv
from claripy.ast.bv import BV
from src.state_plugins import *
from src.simgr_techs import *
from src.utils import *
from src.trace import Trace
from src.claripy_vex_tree import select_a_left_side_sub_tree, convert_claripy_formula_to_vex_tree, TooComplexClaripyFormulaException
from src.function_traces import get_all_functions_of_bin_with_symbols, get_all_func_dump_section_offset
from src.meaningless_blocks import is_meaningless_block
from contextlib import contextmanager
import signal
from src.timeout_pool import TimeoutPool
from src.simplify_pattern import simplify_flatten_constraint
from config import args as smpargs
from src.copyregs import *


AMD64_SKIP_REGS = {'rflags', 'rsp', 'rbp', 'fpsw'}
X86_SKIP_REGS = {'ebp', 'esp', 'eflags'}
# sp is the stack ptr, others are register for special usage.
# nzcv is used as flag registers https://developer.arm.com/docs/ddi0595/b/aarch64-system-registers/nzcv
AARCH64_SKIP_REGS = {'sp', 'x8', 'x16', 'x17', 'x18', 'x29', 'x30', 'nzcv', 'xzr', 'wzr'}

AMD64_RET_REGS = {'rax'}
X86_RET_REGS = {'eax'}
AARCH64_RET_REGS = {'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'}

AMD64_CALL_ARGS_REGS = {'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'edi', 'esi', 'edx', 'ecx'}
X86_CALL_ARGS_REGS = {'edx', 'ecx'}
AARCH64_CALL_ARGS_REGS = {'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'}

special_regs = {
    '<Arch AMD64 (LE)>': (AMD64_SKIP_REGS, AMD64_RET_REGS, AMD64_CALL_ARGS_REGS),
    'X86': (X86_SKIP_REGS, X86_RET_REGS, X86_CALL_ARGS_REGS),
    '<Arch AARCH64 (LE)>': (AARCH64_SKIP_REGS, AARCH64_RET_REGS, AARCH64_CALL_ARGS_REGS)
}

ALL_OPS = dict()


class AngrSimRunTimeoutException(Exception):

    def __init__(self, init_state_addr):
        super(AngrSimRunTimeoutException, self).__init__()
        self.addr = init_state_addr

    def __str__(self):
        return "AngrSimRunTimeoutException, with initial state at address 0x%x" % self.addr

    def __repr__(self):
        return str(self)


@contextmanager
def angr_symbolic_run_time_limit(seconds, block_id):
    """
    to set the timeout for z3 solver
    modify claripy/backends/backend_z3.py around line 768, insert following lines
    # added by WANG Huaijin
    solver.set('timeout', 3 * 1000)
    # ended WANG Huaijin
    """
    def signal_handler(signum, frame):
        raise AngrSimRunTimeoutException(block_id)

    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)


class StateFormulaExtractor:

    def __init__(self, p: angr.Project):
        self.arch = str(p.arch)
        self.skip_regs, self.ret_regs, self.args_regs = special_regs[self.arch]
        self._bvs_map = None
        self.external_functions = get_proj_external_functions_symbols(p)
        self._trim_additional_constraints_func = StateFormulaExtractor.trim_additional_constraints_angr8
        if angr.__version__[0] == 9:
            self._trim_additional_constraints_func = StateFormulaExtractor.trim_additional_constraints_angr9

    @staticmethod
    def trim_additional_constraints_angr9(state):
        trim_additional = []
        for c in state.solver.constraints:
            go_next_itr = False
            for ac in state.memaddr.additional_constraints:
                if c is ac:
                    go_next_itr = True
                    break
            if go_next_itr:
                continue
            trim_additional.append(c)
        return trim_additional

    @staticmethod
    def trim_additional_constraints_angr8(state):
        # different from angr9, the constraints saved in state.memaddr.additional_constraints are strings
        trim_additional = []
        for c in state.solver.constraints:
            if c.depth < 10 and str(c) in state.memaddr.additional_constraints:
                # for too complex constraint item, it is not likely to be an additional constraint
                # anyway it will be trimmed to a subtree for encoding
                continue
            trim_additional.append(c)
        return trim_additional

    def trim_invalid_constraints(self, constraints):
        valid_constraints = []
        for c in constraints:
            valid = True
            if c.depth == 1 and c.op == 'BoolV' and c.args == (True,):
                # add redundant True constraints, <Bool True>
                valid = False
            else:
                if c.depth > 20:
                    # discard too complex constraint
                    # valid = False
                    # continue
                    c = select_a_left_side_sub_tree(c, 20)
                all_inputs = get_expression_input(c, with_extract=False)
                for i in all_inputs:
                    name = angr_symbolic_name(i)
                    if name in self.skip_regs:
                        valid = False
                        break
            if valid:
                valid_constraints.append(c)
        return valid_constraints

    @staticmethod
    def get_writing_mem_formulas(old_state, new_state, valid_mem_addrs: set = None, endness='little'):
        if valid_mem_addrs is None or len(valid_mem_addrs) == 0:
            changed_mem_addr_set = new_state.memory.changed_bytes(old_state.memory)
        else:
            # the memory needs to be read is fixed
            changed_mem_addr_set = valid_mem_addrs
        # here are changed bytes, we need to merge continuous bytes.
        # fortunately, angr symbolizes the bytes being used in continuous way.
        formulas = dict()
        # continuous bytes use the same formula, save the string in right_side to avoid redundancy.
        right_sides = set()
        for addr in changed_mem_addr_set:
            if valid_mem_addrs and addr not in valid_mem_addrs:
                continue
            try:
                if new_state.memory.mem[addr] is None:
                    continue
            except:
                continue
            # sometimes the formula could be extremely complex, (observed 23 depth, over 100 thousand nodes)
            # we merely select the a small subtree of it
            # do not ignore it, it contains too much info
            tmp_mem_formula = new_state.memory.mem[addr].object
            if not hasattr(tmp_mem_formula, 'depth'):
                continue
            while tmp_mem_formula.depth > 8:
                for arg in tmp_mem_formula.args:
                    if hasattr(arg, 'depth') and 7 <= arg.depth:
                        tmp_mem_formula = arg
                        break
            # the changed value is in mem[addr].object, use ('mem_%x' % addr) as the left side of equations
            mem_obj_str = str(tmp_mem_formula)
            if mem_obj_str in right_sides:
                continue
            right_sides.add(mem_obj_str)
            # because of big and little end arch, the mem may have 'Reverse' operation at the very beginning. Ignore it.
            right_side_ast = tmp_mem_formula
            # if the first op is Reverse, this means this memory points to an object with more than 1 bytes
            # we only use the formulas, so we simply remove this Reverse
            if right_side_ast.op == 'Reverse':
                right_side_ast = right_side_ast.args[0]
            # if the project is little end, we need to reverse the constant value
            if endness == 'little':
                if right_side_ast.depth == 1 and isinstance(right_side_ast, BV) and not right_side_ast.symbolic:
                    right_side_ast = claripy.Reverse(right_side_ast)
            formulas[addr] = right_side_ast
        return formulas

    def get_writing_reg_formulas(self, state):
        formulas = dict()
        for reg_name in self.args_regs:
            formulas[reg_name] = getattr(state.regs, reg_name)
        return formulas

    def claripy_formula_to_tree(self, ast, can_sub_tree, sub_tree_depth):
        try:
            return convert_claripy_formula_to_vex_tree(ast, self._bvs_map, can_sub_tree, sub_tree_depth)
        except TooComplexClaripyFormulaException as e:
            log.warning(str(e))
            return None
        except Exception as e:
            log.error(str(e))
            return None

    def get_external_call_from_bbls(self, bbls):
        ex_call = []
        for bb_addr in bbls:
            if bb_addr in self.external_functions:
                ex_call.append(self.external_functions[bb_addr])
        return ex_call

    @staticmethod
    def get_tracelet_id_by_state(state, state_stash):
        bbl_addrs = tuple(state.history.bbl_addrs)
        if state_stash in ['active', 'inloop']:
            return bbl_addrs + (state.addr,)
        else:
            return bbl_addrs + (None,)

    def convert_angr_state_to_trace(self, state, init_state, state_stash):
        constraints = self._trim_additional_constraints_func(state)
        constraints = self.trim_invalid_constraints(constraints)
        # mem_formulas = self.get_writing_mem_formulas(init_state, state)
        mem_formulas = []
        reg_formulas = self.get_writing_reg_formulas(state)

        self._bvs_map = dict()
        new_constraints = []
        for c in constraints:
            tmp = self.claripy_formula_to_tree(c, True, 10)
            if tmp:
                new_constraints.append(tmp)

        new_mem_formulas = dict()
        for f in mem_formulas:
            tmp = self.claripy_formula_to_tree(mem_formulas[f], True, 10)
            if tmp:
                new_mem_formulas[f] = tmp

        new_info_formulas = dict()
        for f in reg_formulas:
            tmp = self.claripy_formula_to_tree(reg_formulas[f], True, 10)
            if tmp:
                new_info_formulas[f] = tmp

        self._bvs_map = None
        ret = Trace()
        ret.set_blocks(list(state.history.bbl_addrs))
        ret.set_stash(state_stash)
        if state_stash in ['active', 'inloop']:
            ret.set_ip(state.addr)
        else:
            ret.set_ip(None)
        ret.constraints = new_constraints
        ret.heap.mem = new_mem_formulas
        ret.info = new_info_formulas
        # the current block is also considered
        external_calls = self.get_external_call_from_bbls(ret.blocks + (ret.ip,))
        ret.set_external_call_sequence(external_calls)
        return ret


def simgr_state_num(simgr, valid_stashes):
    n = 0
    for stash in valid_stashes:
        n += len(simgr.stashes[stash])
    if 'errored' in valid_stashes:
        n += len(simgr.errored)
    return n


def get_executed_instructions(state):
    p = state.project
    bbl_history = list(state.history.bbl_addrs)
    total_insns = 0
    for bbl_addr in bbl_history:
        total_insns += p.factory.block(addr=bbl_addr).instructions
    return total_insns


def possible_flatten_state_machine_var_assignment_state(state):
    insns = state.block().capstone.insns
    for insn_wrapper in insns:
        insn = insn_wrapper.insn
        if insn.mnemonic in ['mov', 'cmov'] and len(insn.operands) == 2:
            if insn.operands[0].size == 4 and insn.operands[1].size == 4 and insn.operands[1].type == 2:
                tmp = insn.op_str.split(', ')
                if tmp[0] in ['eax', 'ecx']:
                    v = insn.operands[1].reg
                    v_str = '%x' % v
                    if 7 <= len(v_str) <= 8 and v_str not in ['ffffffff', '7fffffff']:
                        return True
    return False


def is_meaningful_block(b):
    return not is_meaningless_block(b)


def is_meaningful_state(s):
    return not is_meaningless_block(s.block())


def is_meaningless_state(s):
    return is_meaningless_block(s.block())


def get_executed_meanlingful_blocks(state):
    p = state.project
    bbl_history = list(state.history.bbl_addrs)
    meaningful_blocks = []
    for bbl_addr in bbl_history:
        if is_meaningless_block(p.factory.block(addr=bbl_addr)):
            continue
        meaningful_blocks.append(bbl_addr)
    return meaningful_blocks


def in_loop(state):
    return LoopLimiterTech.in_loop(state)


# def simplify_flatten_constraint(e):
#     if len(e.args) == 2 and e.op in ['SLE', 'SGE', 'SL', 'SG', '__eq__', '__ne__']:
#         if isinstance(e.args[1], claripy.ast.bv.BV) and e.args[1].length == 32:
#             left_v = e.args[1].args[0]
#             if len(e.args[0].args) == 2 and e.args[0].op in ['__add__']:
#                 if isinstance(e.args[0].args[1], claripy.ast.bv.BV) and e.args[1].length == 32:
#                     right_v = e.args[0].args[1].args[0]
#                     v = left_v - right_v
#                     if v < 0:
#                         v += 0xffffffff + 1
#                     return claripy.ast.Bool(op=e.op, args=(e.args[0].args[0], claripy.BVV(v, 32)))
#     return e


def simplify_state_constraiants(s):
    cs = StateFormulaExtractor.trim_additional_constraints_angr9(s)
    cs = list(map(simplify_flatten_constraint, cs))
    s.solver.constraints.clear()
    s.solver.constraints.extend(cs)


def run_simgr_with_meaningful_blocks(simgr, until, **kwargs):
    tech = TraceletCollectionTech(is_end_state=lambda s: False,
                                  is_meaningless_state=is_meaningless_state,
                                  is_inloop=in_loop)
    simgr.use_technique(tech)
    if smpargs.block_callee:
        func_range = kwargs.pop('func_range')
        block_callee_tech = SimExeUntilTech(until_func=lambda s: s.addr not in func_range, tmp_finish_stash='incallee')
        simgr.use_technique(block_callee_tech)
    if smpargs.callee_limiter:
        callee_limiter = TraceletInCalleeLimiter(callee_trace_max_len=smpargs.callee_limit_len)
        simgr.use_technique(callee_limiter)

    simgr.run(until=until)
    if tech.finish_stash in simgr.stashes.keys():
        simgr.move(from_stash=tech.finish_stash, to_stash='active', filter_func=lambda s: s.solver.satisfiable())
    # if tech.inloop_stash in simgr.stashes.keys():
    #     simgr.move(from_stash=tech.inloop_stash, to_stash='active', filter_func=lambda s: s.solver.satisfiable())
    return simgr


def run_simgr_until(simgr, is_resume_state, resume_until_func, stop_resume_limit=2,
                    inloop_func=in_loop, inloop_stash='inloop'):
    valid_active = []
    errored = []
    p = simgr._project
    for s in simgr.active:
        try:
            if is_resume_state(s):
                # execute until the the state matches requirement
                to_exeute_until_meaningful_simgr = p.factory.simgr(s)
                tmp_tech = SimExeUntilTech(until_func=resume_until_func)
                to_exeute_until_meaningful_simgr.use_technique(
                    SkipMeaninglessBlockConstraintsTech(is_meaningless_state))
                to_exeute_until_meaningful_simgr.use_technique(tmp_tech)
                to_exeute_until_meaningful_simgr.use_technique(LoopLimiterTech())
                finish_stash_str = tmp_tech.get_tmp_finish_stash_str()
                to_exeute_until_meaningful_simgr.run(
                    until=lambda simgr: len(simgr.stashes[finish_stash_str]) >= stop_resume_limit)
                valid_active.extend(to_exeute_until_meaningful_simgr.stashes[finish_stash_str])
            else:
                valid_active.append(s)
        except Exception as e:
            log.error('Problematic state %s, with error %s' % (str(s), str(e)))
            errored.append(s)
    simgr.stashes['active'] = list(filter(lambda s: s.solver.satisfiable(), valid_active))
    simgr.stashes['errored'].extend(errored)
    return simgr


def get_break_loop_successors(simgr, loop_stash, func_range):
    state_list = simgr.stashes[loop_stash]
    tracelet_states = []
    successors = []
    for s in state_list:
        loop_unit = LoopLimiterTech.get_state_loop_unit(s)
        visited_bbs = set(s.history.bbl_addrs)
        s_succs = set()
        if loop_unit is None:
            continue
        bb_in_func = list(filter(lambda addr: addr in func_range, loop_unit))
        if len(bb_in_func) == 0:
            # the whole loop exists in a callee, treat it like ending in a callee
            # append it to active and continue
            ret_addr = find_ret_addr(s, func_range)
            if ret_addr is not None:
                tracelet_states.append((s, 'active'))
                successors.append((s, 'active', 'ret', ret_addr))
            continue
        # if there are blocks in the target function, find the possible place to break
        for bb_addr in bb_in_func:
            tmp_s = create_blank_state(simgr._project, bb_addr)
            try:
                tmp_sucs = tmp_s.step()
                if len(tmp_sucs.flat_successors) > 1:
                    tmp_suc_addr_list = [tmp_succ_state.addr for tmp_succ_state in tmp_sucs.flat_successors]
                    tmp_suc_addr_list = list(filter(lambda addr: addr in func_range and addr not in visited_bbs,
                                                    tmp_suc_addr_list))
                    if len(tmp_suc_addr_list) == 1:
                        s_succs.add(tmp_suc_addr_list[0])
            except Exception as e:
                log.error('Meets error while searching successors for loop')
        if len(s_succs) == 1:
            tracelet_states.append((s, loop_stash))
            successors.append((s, loop_stash, 'exe', list(s_succs)[0]))
        else:
            # TODO: we need to decide which one is the successor if break the loop
            # simply select no successor
            pass
    return tracelet_states, successors


def find_ret_addr(state, func_range):
    call_stack_depth = len(state.callstack)
    if call_stack_depth > 1:
        # find the stack depth directly (avoid bugs)
        ret_addr = state.callstack[call_stack_depth - 2].ret_addr
        if ret_addr in func_range:
            return ret_addr
    return None


def collect_tracelets_and_successors(simgr, visited_entries, state_limit, func_range,
                                     overlap_tracelet, valid_stashes):
    if 'errored' in valid_stashes and simgr.errored:
        # the errored is not saved in simgr.stashes['errored'], but is stored in an attribute of simgr.errored
        # anyway, we move the states of errored to simgr.stashes['errored']
        simgr.stashes['errored'].extend(map(lambda e: e.state, simgr.errored))
    tracelet_states = []
    # for each successor, it is a block entry following a tracelet
    # to save more info, we save the tuple, (father_tracelet_state, success_type, block_entry)
    successors = []
    p = simgr._project
    for stash in valid_stashes:
        for s in simgr.stashes[stash]:
            simplify_state_constraiants(s)
            tracelet_states.append((s, stash))
            if len(tracelet_states) >= state_limit:
                # the number of collected states reaches the uppper limit
                return tracelet_states, successors
            bbl_history = list(s.history.bbl_addrs)
            if stash == 'active':
                bbl_history.append(s.addr)
            if overlap_tracelet:
                for bbl_entry in bbl_history:
                    if bbl_entry in func_range:
                        if is_meaningless_block(p.factory.block(addr=bbl_entry)):
                            continue
                        if bbl_entry not in visited_entries:
                            successors.append((s, stash, 'exe', bbl_entry))
            else:
                # if no overlap, simply add the last active address
                if stash == 'active' and len(s.callstack) <= 1 and s.addr in func_range:
                    successors.append((s, stash, 'exe', s.addr))
            # the address is not in the range of current function
            # push return address in to stack
            if stash in ['active', 'unconstrained', 'errored', 'incallee', 'toolongincallee']:
                ret_addr = find_ret_addr(s, func_range)
                if ret_addr is not None and ret_addr not in visited_entries:
                    successors.append((s, stash, 'ret', ret_addr))
    return tracelet_states, successors


def get_successors_relation(successors):
    relations = dict()
    for succ_tuple in successors:
        father_state, father_stash, succ_type, succ_head = succ_tuple
        father_tracelet_id = StateFormulaExtractor.get_tracelet_id_by_state(father_state, father_stash)
        relations[father_tracelet_id] = (succ_head, succ_type)
    return relations


def is_flatten_state_machine_var_assignment(capstone_insn):
    """
    return the tuple of reg_name, state_machine_var if it is true; None otherwise
    """
    if capstone_insn.mnemonic == 'mov' and len(capstone_insn.operands) == 2:
        if capstone_insn.operands[0].size == 4 and capstone_insn.operands[1].size == 4:
            reg_name = capstone_insn.reg_name(capstone_insn.operands[0].reg)
            v = capstone_insn.operands[1].reg
            v_str = '%x' % v
            if 7 <= len(v_str) <= 8 and v_str not in ['ffffffff', '7fffffff']:
                return reg_name, v
    return None, None


def cache_fla_state_variables(f_start, func_range, p: angr.Project, valid_stashes):
    """
    The beginning for a flatten function will initialize some variables, store them in registers which will not be used frequently
    """
    tmp_state = create_blank_state(p, f_start, [])
    # execute until the first jump, skip all callees
    tmp_simgr = p.factory.simgr(tmp_state)
    skip_callees_tech = SkipCalleesTech(func_range)
    tmp_simgr.use_technique(skip_callees_tech)

    def until_jump_insn(simgr):
        if simgr_state_num(simgr, valid_stashes) > 1:
            return True
        if len(simgr.active) > 0:
            bbl_history = list(simgr.active[0].history.bbl_addrs)
            if len(bbl_history) == 0:
                return False
            last_bb = p.factory.block(addr=bbl_history[-1])
            if last_bb.capstone.insns[-1].insn.mnemonic.startswith('j'):
                return True
        return False

    tmp_simgr.run(until=until_jump_insn)

    # get the state
    the_state = None
    for stash in valid_stashes:
        if len(tmp_simgr.stashes[stash]) > 0:
            the_state = tmp_simgr.stashes[stash][0]
            break
    if the_state is None and 'errored' in valid_stashes:
        if len(tmp_simgr.errored) > 0:
            the_state = tmp_simgr.errored[0].state

    # get the stateVar for state machine
    cached_vars = dict()
    for b_addr in the_state.history.bbl_addrs:
        bb = p.factory.block(addr=b_addr)
        for insn in bb.capstone.insns:
            capstone_insn = insn.insn
            reg, var = is_flatten_state_machine_var_assignment(capstone_insn)
            if reg is None:
                continue
            cached_vars[reg] = var
    if 'eax' in cached_vars:
        cached_vars.pop('eax')
    # if 'ecx' in cached_vars:
    #     cached_vars.pop('ecx')
    ret_cached = dict()
    for reg in cached_vars:
        if (getattr(the_state.regs, reg) == cached_vars[reg]).args[0] is True:
            ret_cached[reg] = getattr(the_state.regs, reg)
    return ret_cached


def assign_state_machine_regs(state, state_vars):
    for reg in state_vars:
        setattr(state.regs, reg, state_vars[reg])


def get_func_tracelets(f_start, func_insn_addrs: list, p: angr.Project, max_state=3, valid_stashes=None,
                       state_limit=2000,
                       overlap_tracelet=smpargs.overlap_tracelet,
                       copy_regs=smpargs.copy_regs):
    """
    func_insn_addrs is a sorted list
    """
    visited_entries = dict()
    stack = [(None, 'active', 'exe', f_start)]
    # this are states to do further execution (few have learned from limited tracelet length)
    all_states = []
    succ_relations = dict()
    func_range = range(f_start, func_insn_addrs[-1] + 1)
    upper_limit_per_run = max_state
    if copy_regs:
        copy_regs_func = get_copy_regs_func_ptr(p)

    if valid_stashes is None:
        valid_stashes = ['active', 'unconstrained', 'deadended', 'errored', 'toolongincallee']
    if smpargs.block_callee:
        valid_stashes.append('incallee')

    use_plugins = ['memaddr']
    if smpargs.callee_limiter:
        use_plugins.append('callee_limiter')

    fla_state_variables = None
    if smpargs.is_flatten:
        fla_state_variables = cache_fla_state_variables(f_start, func_range, p, valid_stashes)

    while stack:
        father, father_stash, succ_type, tmp_entry = stack.pop()
        if tmp_entry in visited_entries:
            continue

        tmp_state = create_blank_state(p, tmp_entry, use_plugins)

        if copy_regs and father is not None and succ_type == 'exe':
            # to handle with ollvm -fla (control flow flattening), save the StateVar for the state machine
            # refer details on https://rpis.ec/blog/dissection-llvm-obfuscator-p1/
            # simply copy the value of eax and ecx
            # may not for ollvm -fla specifically, all such situation could success the registers, even stack value from its father
            # success the value of registers here
            copy_regs_func(father, tmp_state)
        try:
            if len(tmp_state.block().instruction_addrs) == 0:
                log.error('problematic block with no instruction 0x%x' % tmp_state.addr)
                continue
        except angr.errors.SimEngineError as e:
            log.error('problematic block 0x%x with error (%s)' % (tmp_entry, str(e)))
            continue
        if tmp_state.block().instruction_addrs[-1] not in func_range:
            # the whole block should exist in the range this function; or it's a problematic block
            continue
        # print(len(all_states), 'SE %s' % str(tmp_state), str(get_executed_meanlingful_blocks(tmp_state)), str(list(tmp_state.history.bbl_addrs)))
        visited_entries[tmp_entry] = tmp_state

        if len(all_states) > 0 and smpargs.is_flatten:
            assign_state_machine_regs(tmp_state, fla_state_variables)

        tmp_simgr = p.factory.simgr(tmp_state)
        simgr_until = lambda m: simgr_state_num(m, valid_stashes) >= upper_limit_per_run or \
                                simgr_state_num(m, valid_stashes) >= (state_limit - len(all_states))
        try:
            if sys.platform != 'win32':
                with angr_symbolic_run_time_limit(60, tmp_state.addr):
                    run_simgr_with_meaningful_blocks(tmp_simgr, until=simgr_until, func_range=func_range)
            else:
                run_simgr_with_meaningful_blocks(tmp_simgr, until=simgr_until, func_range=func_range)
        except AngrSimRunTimeoutException as e:
            log.error('timeout while running state at 0x%x' % tmp_entry)
            # do not execute and continue
            if len(tmp_simgr.active) == 1 and tmp_simgr.active[0].addr == tmp_entry:
                skip_the_active = True
                for stash in valid_stashes:
                    if stash == 'active':
                        continue
                    if len(tmp_simgr.stashes[stash]) > 0:
                        skip_the_active = False
                        break
                if skip_the_active:
                    continue
        except Exception as e:
            log.error(str(e) + ' while running state at 0x%x' % tmp_entry)
            # do not execute and continue
            if len(tmp_simgr.active) == 1 and tmp_simgr.active[0].addr == tmp_entry:
                skip_the_active = True
                for stash in valid_stashes:
                    if stash == 'active':
                        continue
                    if len(tmp_simgr.stashes[stash]) > 0:
                        skip_the_active = False
                        break
                if skip_the_active:
                    continue
        # sometimes, such as control flow flattening, there will be lots of meaningless conditional jump
        # in the pattern of `cmp eax, constant; jz/jl/jnz/... loc_xxxx`
        # for such situations, the executed instructions are relatively few, then do further steps
        # here, the average instructions being executed in average per block should be larger than 4
        tmp_simgr = run_simgr_until(tmp_simgr,
                                    is_resume_state=is_meaningless_state,
                                    resume_until_func=is_meaningful_state,
                                    stop_resume_limit=2,
                                    inloop_func=in_loop,
                                    inloop_stash='inloop')

        tracelet_states, successors = collect_tracelets_and_successors(tmp_simgr, visited_entries,
                                                                       state_limit=(state_limit - len(all_states)),
                                                                       func_range=func_range,
                                                                       overlap_tracelet=overlap_tracelet,
                                                                       valid_stashes=valid_stashes)

        if not smpargs.without_inloop:
            loop_tracelet_states, loop_successors = get_break_loop_successors(tmp_simgr, 'inloop', func_range)
            tracelet_states.extend(loop_tracelet_states)
            successors.extend(loop_successors)

        all_states.extend(tracelet_states)
        stack.extend(successors)
        # assert no collision of keys
        tmp_relations = get_successors_relation(successors)
        for k in tmp_relations.keys():
            assert k not in succ_relations
        succ_relations.update(tmp_relations)

    return all_states, visited_entries, succ_relations


def get_func_tracelets_multiprocess(fname, f_start, func_insn_addrs: list, p: angr.Project, dump_dir, max_state=3,
                                    valid_stashes=None, state_limit=2000):
    default_recursive_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(10000)
    start_time = time.time()
    tmp_states, tmp_init_states, succ_relations = get_func_tracelets(f_start, func_insn_addrs, p, max_state=max_state,
                                                     valid_stashes=valid_stashes, state_limit=state_limit)
    # tmp_states = list(map(StateFormulaExtractor.trim_additional_constraints_angr8, tmp_states))
    sfe = StateFormulaExtractor(p)
    tracelets = []
    for ts, tstash in tmp_states:
        ts_init_addr = get_state_first_bbl_addr(ts)
        if ts_init_addr is None:
            continue
        tmp_tracelet = sfe.convert_angr_state_to_trace(ts, tmp_init_states[ts_init_addr], tstash)
        tracelets.append(tmp_tracelet)
    dump_path = os.path.join(dump_dir, '%x.%s.pkl' % (f_start, fname))
    try:
        with open(dump_path, 'wb') as df:
            pickle.dump((tracelets, succ_relations), df)
    except Exception as e:
        log.error("Fail to dump %s, because of %s" % (dump_path, str(e)))
    finally:
        span = time.time() - start_time
        log.error("%.06f seconds for function 0x%x" % (span, f_start))
        sys.setrecursionlimit(default_recursive_limit)


def get_state_first_bbl_addr(state):
    for addr in state.history.bbl_addrs:
        return addr


ignore_funcs = {
    (0x0, '_start'),
    (0x0, '__libc_csu_init'),
    (0x0, '__libc_csu_fini'),
    (0x0, 'atexit'),
    (0x0, '__stat'),
    (0x0, '__fstat')
}
ignore_func_names = set([f[1] for f in ignore_funcs])


def get_all_tracelets(bin_path, skip_exists=False):
    """
    angr tracelet is a state
    It is possible to convert a state to a trace
    """
    p = load_proj(bin_path)
    # sec_offset = get_all_func_dump_section_offset(p, p.filename + '.func.dump')
    # functions = get_all_functions_of_bin_with_symbols(bin_path, sec_offset)
    functions = get_all_functions_of_bin_with_symbols(bin_path, get_offset(p))
    dump_dir = get_angr_pkl_path(bin_path)
    if not os.path.isdir(dump_dir):
        os.mkdir(dump_dir)
    target_func_addr = None
    target_func_name = None
    if smpargs.target_func is not None:
        if smpargs.target_func.startswith('0x'):
            target_func_addr = int(smpargs.target_func, 16)
        elif smpargs.target_func.startswith('0'):
            target_func_addr = int(smpargs.target_func)
        elif len(smpargs.target_func) > 0:
            target_func_name = smpargs.target_func
    for fname, func_insns in functions.items():
        if target_func_addr is not None and fname[0] != target_func_addr:
            continue
        if target_func_name is not None and fname[1] != target_func_name:
            continue
        if fname[1] in ignore_func_names:
            continue
        if skip_exists:
            dump_path = os.path.join(dump_dir, '%x.%s.pkl' % (fname[0], fname[1]))
            if os.path.isfile(dump_path) and os.path.getsize(dump_path) > 2048:
                # 6 bytes is an empty list
                log.warning('skip ' + str(fname))
                continue
        log.warning('Getting function tracelets ' + str(fname) + ' ' + str(func_insns[-1]))
        get_func_tracelets_multiprocess(fname[1], fname[0], func_insns, p, dump_dir, smpargs.max_state, None,
                                        state_limit=smpargs.tracelet_limit)


def get_all_tracelets_multiprocess(bin_path,
                                   skip_exists=False,
                                   skip_fnames=None):
    p = load_proj(bin_path)
    functions = get_all_functions_of_bin_with_symbols(bin_path, get_offset(p))
    dump_dir = get_angr_pkl_path(bin_path)
    if not os.path.isdir(dump_dir):
        os.mkdir(dump_dir)
    args_list = []
    for fname, func_insns in functions.items():
        if skip_exists:
            dump_path = os.path.join(dump_dir, '%x.%s.pkl' % (fname[0], fname[1]))
            if os.path.isfile(dump_path) and os.path.getsize(dump_path) > 512:
                # 6 bytes is an empty list
                log.warning('skip ' + str(fname))
                continue
        if skip_fnames is not None:
            if fname[1] in skip_fnames:
                log.warning('skip2 ' + str(fname))
                continue
        if fname[1] in ignore_func_names:
            continue
        # in coreutils (-O0), 3 functions have the same name do_encode (slightly different)
        # so I add function entry as a part of fname
        args_list.append((fname[1], fname[0], func_insns, p, dump_dir, smpargs.max_state, None, smpargs.tracelet_limit))
    if skip_exists:
        for args in args_list:
            log.warning('Handle ' + str(args[0]))
    pool = TimeoutPool(smpargs.process, smpargs.timeout, smpargs.mem_limit)
    pool.map(get_func_tracelets_multiprocess, args_list)


def get_all_tracelets_multiprocess2(bin_path_list,
                                    skip_exists=False,
                                    skip_fnames=None,
                                    skip_same_fnames=False):
    args_list = []
    fnames_set = set()
    for bin_path in bin_path_list:
        log.warning(f'loading {bin_path}')
        p = load_proj(bin_path)
        # sec_offset = get_all_func_dump_section_offset(p, p.filename + '.func.dump')
        # functions = get_all_functions_of_bin_with_symbols(bin_path, sec_offset)
        functions = get_all_functions_of_bin_with_symbols(bin_path, get_offset(p))
        dump_dir = get_angr_pkl_path(bin_path)
        if not os.path.isdir(dump_dir):
            os.mkdir(dump_dir)
        for fname, func_insns in functions.items():
            if skip_same_fnames:
                if fname[1] != 'main' and fname[1] in fnames_set:
                    continue
            fnames_set.add(fname[1])

            if skip_exists:
                dump_path = os.path.join(dump_dir, '%x.%s.pkl' % (fname[0], fname[1]))
                if os.path.isfile(dump_path) and os.path.getsize(dump_path) > 1024:
                    # 6 bytes is an empty list
                    log.warning('skip ' + str(fname))
                    continue
            if skip_fnames is not None:
                if fname[1] in skip_fnames:
                    log.warning('skip2 ' + str(fname))
                    continue
            if fname[1] in ignore_func_names:
                continue
            # in coreutils (-O0), 3 functions have the same name do_encode (slightly different)
            # so I add function entry as a part of fname
            args_list.append((fname[1], fname[0], func_insns, p, dump_dir, smpargs.max_state, None, smpargs.tracelet_limit))
    if skip_exists:
        for args in args_list:
            log.warning('Handle ' + str(args[0]) + ' ' + str(args[3]))
    pool = TimeoutPool(smpargs.process, smpargs.timeout, smpargs.mem_limit)
    pool.map(get_func_tracelets_multiprocess, args_list)
