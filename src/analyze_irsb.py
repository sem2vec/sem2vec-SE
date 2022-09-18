import sys
import copy
import pickle
from src.vex_tree_utils import Tree

from src.trace import Trace, merge_2_traces
from src.trace_process import *
from src.utils import log
from src.vex_ir_preprocess import *

dec_re = re.compile('[0-9]+')
hex_re = re.compile('0x[0-9a-fA-F]+')


def _get_used_var(t: Tree):
    """
    add used variables to a set, and return
    """
    var_set = set()
    stack = [t]
    while len(stack) > 0:
        tmp = stack.pop()
        if tmp.data == 'var':
            var_set.add(get_var_str(tmp))
        elif len(tmp.children) > 0:
            stack.extend(filter(lambda item: isinstance(item, Tree), tmp.children))
    return var_set


def _analyze_an_assignment(t: Tree):
    _ijk_type = None
    if len(t.children) > 1:
        _ijk_type = get_var_str(t.children[1])
    left = t.children[0].children[0]
    right = t.children[0].children[1]
    if left.data == 'var':
        return ('tmp', get_var_str(left)), (right, _get_used_var(right)), _ijk_type
    elif left.data == 'fun':
        fname = get_fname_str(left.children[0])
        if fname == 'PUT':
            # write into register
            reg_name = get_var_str(left.children[1].children[0])
            return ("reg", reg_name), (right, _get_used_var(right)), _ijk_type
        elif fname == 'PutI':
            return GetI_PutI_key(left), (right, _get_used_var(right)), _ijk_type
        elif fname == 'STle':
            # save to memory
            var_name = get_var_str(left.children[1].children[0])
            return ("deref", var_name), (right, _get_used_var(right)), _ijk_type
        else:
            raise Exception('unknown left hand\n' + left.pretty())


def _analyze_an_if(t: Tree):
    condition = t.children[0].children[0]
    ifstmt = t.children[0].children[1]
    assert condition.data == 'var'
    assert ifstmt.children[0].data == 'assign_expr'
    if len(t.children[0].children) == 2:
        return get_var_str(condition), _analyze_an_assignment(ifstmt)
    elif len(t.children[0].children) == 3:
        elsestmt = t.children[0].children[2]
        return get_var_str(condition), _analyze_an_assignment(ifstmt), _analyze_an_assignment(elsestmt)


def _analyze_a_tree(t: Tree):
    if t.children[0].data == 'assign_expr':
        return '=', _analyze_an_assignment(t)
    elif t.children[0].data == 'if':
        return 'if', _analyze_an_if(t)
    else:
        raise NotImplementedError()


def is_end_block_ijk(ijk):
    return ijk in ['Ijk_Boring', 'Ijk_Call', 'Ijk_Ret']


def compress_block_info(infos):
    num_stmts = len(infos)
    traces = [Trace()]  # each trace is a 2-element list, [constraint, trace_info]
    for idx in range(num_stmts):
        _type, info = infos[idx]
        if _type == '=':
            left_info, right_info, ijk_type = info
            right_tree, ref_vars = right_info
            # update the info in each trace
            log.debug('left info: ' + str(left_info))
            for trace in traces:
                trace.add_assignment(left_info, right_tree)
            if idx == num_stmts - 1:
                for trace in traces:
                    trace.set_last_ijk_type(ijk_type)

        elif _type == 'if':
            condition_var = info[0]
            left_info, right_info, ijk_type = info[1]
            right_tree, ref_vars = right_info
            else_traces = []
            if_traces = []
            for trace in traces:
                has_true = True
                has_false = True
                condition_tree = trace.get_from_info_with_key(('tmp', condition_var))
                if is_num(condition_tree):
                    if get_num(condition_tree) == 0:
                        # no true condition
                        has_true = False
                    elif get_num(condition_tree) == 1:
                        # no false condition
                        has_false = False
                # the conditional variable is always a tmp value
                not_condition_tree = get_not_tree(condition_tree)
                else_trace = trace.copy()
                # else constraints must be built before update if constraints
                else_trace.append_constraints(not_condition_tree)
                # the if branch, do change
                trace.append_constraints(condition_tree)
                trace.add_assignment(left_info, right_tree)

                if idx == num_stmts - 1:
                    trace.set_last_ijk_type(ijk_type)
                    # it seems the ijk_type of else branch is always the same as that of if branch
                    else_trace.set_last_ijk_type(ijk_type)
                # if len(info) == 2:
                # the else branch has no statement
                # pass
                elif has_false and len(info) == 3:
                    else_left_info, else_right_info, else_ijk_type = info[2]
                    else_right_tree, else_ref_vars = else_right_info
                    else_trace.add_assignment(else_left_info, else_right_tree)
                if has_false:
                    else_traces.append(else_trace)
                if has_true:
                    if_traces.append(trace)
            traces = if_traces + else_traces
    # filter all ('tmp', ...) info
    for trace in traces:
        trace.refine()
    return traces


def analyze_a_block(stmts: list, insns_map):
    """
    The elements in stmts are (insn_addr, [statement])
    statements are grouped by instructions
    """
    # we first do block raw statements level preprocess
    if last_2_statements_are_conditional_jump(stmts[-1][1]):
        stmts[-1] = (stmts[-1][0], convert_last_2_statements_to_if_else_ip_assignment(stmts[-1][1]))

    vex_trees_info = []
    for insn_addr, insn_stmts in stmts:
        insn_str = insns_map[insn_addr]
        for insn_stmt in insn_stmts:
            try:
                # do statement level checks
                # we do not convert statement of floating point relative instruction
                # the vex IR for floating point relative instruction is very complex and introduce branches
                stmt = raw_stmt_check_and_modify(insn_stmt, insn_str)
                if stmt is None:
                    # this statement is useless. Skip it!
                    continue
                tmp = parser.parse(stmt)
                tmp = lark_tree_to_tree(tmp)
            except Exception as e:
                raise Exception(str(e) + "\n" + insn_stmt)
            vex_trees_info.append(_analyze_a_tree(tmp))
    traces = compress_block_info(vex_trees_info)
    return traces


def extend_1_block(traces, block_traces: dict):
    """
    tarces is the the traces to be extended, the content of this list could be changed
    block_traces is the data of all blocks, the content of this dictionary is never changed
    We use the value of ip register to select the block to extend.
    If exact rip value is not available, we cannot extend the trace
    TODO: we could use the result of IDA pro/angr CFG to help us determine which block is the following one.
    """
    extended = []
    not_extendable = []
    for trace in traces:
        # select the next block
        next_b_id = trace.get_next_insn_addr()
        if next_b_id is None:
            not_extendable.append(trace.copy())
            continue
        if next_b_id not in block_traces.keys():
            log.warning('the next block is not cached b_id = 0x%x' % next_b_id)
            # TODO this could be libcalls, we could simple skip it and move rip to the next instruction
            # some functions other than printf have side-effect on current state, not sure what to do
            not_extendable.append(trace.copy())
            continue
        for next_t in block_traces[next_b_id]:
            try:
                log.debug('extend to 0x%x' % next_b_id)
                tmp_trace = merge_2_traces(trace, next_t)
                extended.append(tmp_trace)
            except Exception as e:
                log.error(str(e) + ' while extending to 0x%x' % next_b_id)
    return extended, not_extendable


def get_tracelet_n(block_traces: dict, block_limit: int, tracelet_limit: int):
    """
    n = 2^a1 + 2^a2 + ...
    we could accelerate the process when n is large (but we merely meet max n=3)
    """
    if block_limit <= 1:
        return block_traces
    res = dict()
    for b_id, traces in block_traces.items():
        log.debug('extending 0x%x' % b_id)
        tmp_ext = traces
        tmp_noext = []
        for i in range(block_limit - 1):
            log.debug('step %d' % (i + 1))
            tmp_ext, tmp_fail = extend_1_block(tmp_ext, block_traces)
            tmp_noext.extend(tmp_fail)
            if len(tmp_ext) + len(tmp_fail) >= tracelet_limit:
                break
        res[b_id] = tmp_ext + tmp_noext
    # normalize
    log.debug('normalize traces')
    for b_id in res.keys():
        for t in res[b_id]:
            t.normalize()
    return res


def extend_tracelet_to_length_n(to_be_extended, block_traces: dict, block_limit: int, tracelet_limit: int,
                                normalize=True):
    """
    n = 2^a1 + 2^a2 + ...
    we could accelerate the process when n is large (but we merely meet max n=3)
    """
    if block_limit <= 1:
        return to_be_extended
    tmp_ext = to_be_extended
    tmp_noext = []
    for i in range(block_limit - 1):
        log.debug('step %d' % (i + 1))
        tmp_ext, tmp_fail = extend_1_block(tmp_ext, block_traces)
        tmp_noext.extend(tmp_fail)
        if len(tmp_ext) + len(tmp_fail) >= tracelet_limit:
            break

    if normalize:
        for trace in tmp_ext:
            trace.normalize()
        for trace in tmp_noext:
            trace.normalize()
    return tmp_ext, tmp_noext


def dump_bb_tree_info(raw_irsb_path, insns_map, dump_path):
    irsbs = read_IRSBs(raw_irsb_path)
    res = dict()
    for irsb in irsbs:
        stmts = vex_block_to_statements(irsb[1])
        try:
            tmp = analyze_a_block(stmts, insns_map)
            for _t in tmp:
                _t.set_blocks([irsb[0]])
            res[irsb[0]] = tmp
        except Exception as e:
            log.error('While analyzing IRSB 0x%x, meet Exception ' % irsb[0] + str(e))
        # tmp = analyze_a_block(stmts, insns_map)
        # res[irsb[0]] = tmp
    recursive_limit = sys.getrecursionlimit()
    # the pickle.dump may exceed the recursive limit
    sys.setrecursionlimit(recursive_limit * 10)
    with open(dump_path, 'wb') as f:
        pickle.dump(res, f)
