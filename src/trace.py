"""
It is used to store the info after traverse all statements of one or more blocks
The analysis result is a list of trace
"""
from copy import deepcopy

from src.symbolic_heap import SymbolicHeap
from src.symbolic_stack import SymbolicStack
from src.trace_process import naive_hard_simplify
from src.utils import log
from src.vex_tree_utils import *

import angr
import networkx as nx


class UnrecognizableAddressExpressionException(Exception):
    pass


class Trace:

    def __init__(self):
        self.normalized = False
        self.constraints = []
        self.info = dict()  # in most cases, it is used for register info
        self.stack = SymbolicStack()
        self.heap = SymbolicHeap()
        self.last_ijk_type = None
        self.blocks = []  # all blocks being covered by this trace
        self.ip = None
        self.stash = None
        self.excall_seq = []

    def set_last_ijk_type(self, ijk_type):
        self.last_ijk_type = ijk_type

    def set_blocks(self, blocks: list):
        self.blocks = tuple(blocks)

    def set_ip(self, ip):
        self.ip = ip

    def set_stash(self, stash):
        self.stash = stash

    def set_external_call_sequence(self, seq):
        self.excall_seq = seq

    @property
    def id(self):
        # the same block history could result in different destinations
        return self.blocks + (self.ip,)

    def _append_constraint(self, cons):
        # new_cons = self._replace_var_with_tree(cons)
        # the cons is always read from self.info
        new_cons = deepcopy(cons)
        self.constraints.append(new_cons)

    def append_constraints(self, _constraints):
        if isinstance(_constraints, list):
            for c in _constraints:
                self._append_constraint(c)
        elif isinstance(_constraints, Tree):
            self._append_constraint(_constraints)
        else:
            raise Exception('Wrong constraints argument')

    def read_from_memory(self, mem_addr_expr: Tree):
        base, offset = SymbolicStack.get_base_and_offset(mem_addr_expr)
        if offset is None:
            tmp = None
        elif base is None:
            # read from heap, it could be None
            tmp = self.heap.read_item(offset)
        else:
            # read from stack, it could be None
            tmp = self.stack.read_item(base, offset)
        return tmp

    def save_into_memory(self, mem_addr_expr: Tree, value_expr: Tree):
        base, offset = SymbolicStack.get_base_and_offset(mem_addr_expr)
        if offset is None:
            raise UnrecognizableAddressExpressionException(
                'Un-recognizable address expression! ' + tree2str(mem_addr_expr))
        elif base is None:
            self.heap.save_item(offset, value_expr)
        else:
            self.stack.save_item(base, offset, value_expr)

    def _replace_LD_var(self, t: Tree) -> Tree:
        """
        This means it loads value from memory
        """
        # LDle has only 1 argument
        arg = get_fun_args(t)[0]
        if arg.data == 'var':
            var_str = get_var_str(arg)
            mem_addr_expr = self.info[('tmp', var_str)]
        else:
            mem_addr_expr = self.replace_var_with_info(arg)
        tmp = self.read_from_memory(mem_addr_expr)
        if tmp is None:
            # cannot find the node being assigned to address mem_addr_expr
            # then we update the mem_addr_expr itself
            return create_fun_tree(fname_tokens=get_fun_fname_tokens(t), args=[deepcopy(mem_addr_expr)])
        else:
            return deepcopy(tmp)

    def replace_var_with_info(self, t: Tree) -> Tree:
        if t.data == 'var':
            var_key = var_to_key(t)
            if var_key in self.info.keys():
                return deepcopy(self.info[var_key])
        elif is_LDle(t):
            return self._replace_LD_var(t)
        elif is_GetI(t):
            key = GetI_PutI_key(t)
            if key in self.info.keys():
                return deepcopy(self.info[key])
        elif is_GET_reg(t):
            reg_name = GET_reg_name(t)
            if ('reg', reg_name) in self.info.keys():
                return deepcopy(self.info[('reg', reg_name)])
            else:
                return t

        new_children = []
        for c in t.children:
            if isinstance(c, Tree):
                new_children.append(self.replace_var_with_info(c))
            else:
                new_children.append(c)
        ret = Tree(t.data, new_children)
        if ret.size > 2000:
            raise Exception('Too large Tree!')
        return ret

        # ret = deepcopy(t)
        # stack = [ret]
        # while len(stack) > 0:
        #     tmp = stack.pop()
        #     for idx in range(len(tmp.children)):
        #         child = tmp.children[idx]
        #         if isinstance(child, Tree):
        #             if child.data == 'var':
        #                 var_key = var_to_key(child)
        #                 if var_key in self.info.keys():
        #                     # tmp.children[idx] = deepcopy(self.info[var_key])
        #                     tmp.replace_child(idx, deepcopy(self.info[var_key]))
        #             elif is_LDle(child):
        #                 # tmp.children[idx] = self._replace_LD_var(child)
        #                 tmp.replace_child(idx, self._replace_LD_var(child))
        #             elif is_GetI(child):
        #                 key = GetI_PutI_key(child)
        #                 if key in self.info.keys():
        #                     # tmp.children[idx] = deepcopy(self.info[key])
        #                     tmp.replace_child(idx, deepcopy(self.info[key]))
        #             elif is_GET_reg(child):
        #                 reg_name = GET_reg_name(child)
        #                 if ('reg', reg_name) in self.info.keys():
        #                     # tmp.children[idx] = deepcopy(self.info[('reg', reg_name)])
        #                     tmp.replace_child(idx, deepcopy(self.info[('reg', reg_name)]))
        #             else:
        #                 stack.append(child)
        # return ret

    def get_from_info_with_key(self, key):
        return self.info[key]

    def add_assignment(self, left_info, right_formula_tree: Tree):
        """
        see _analyze_an_assignment to know more about left_info
        """
        log.debug('original right expression: ' + tree2str(right_formula_tree))
        new_right_tree = self.replace_var_with_info(right_formula_tree)
        log.debug('updated right expression:  ' + tree2str(new_right_tree))
        new_right_tree = naive_hard_simplify(deepcopy(new_right_tree))
        log.debug('simplified right expression:  ' + tree2str(new_right_tree))
        if left_info[0] == 'reg' or left_info[0] == 'tmp':
            self.info[left_info] = new_right_tree
        elif left_info[0] == 'deref':
            # it tries to save value into memory
            # the address is always a tmp value for a vex assignment statement
            if ('tmp', left_info[1]) in self.info:
                mem_addr_expr = self.info[('tmp', left_info[1])]
                try:
                    self.save_into_memory(mem_addr_expr, new_right_tree)
                except UnrecognizableAddressExpressionException as e:
                    log.warning(str(e))
                    # cannot handle it currently, save it in info dictionary
                    self.info[left_info] = new_right_tree
            else:
                # left_info[1] could be a fixed address
                # TODO: handle it later
                pass
        else:
            # TODO ('derefarr__xn__xxx', 't_n', 'y') is also saved in the dictionary
            pass

    def refine(self):
        """
        remove useless tmp values
        """
        useless = []
        for _type, _tname in self.info.keys():
            if _type == 'tmp' and ('deref', _tname) not in self.info.keys():
                useless.append((_type, _tname))
        for item in useless:
            self.info.pop(item)

    def _get_return_type_rip_assignment(self, rip_expr):
        for tmp_base in ['rsp', 'rbp']:
            if is_LDle(rip_expr) and ('reg', tmp_base) in self.info:
                arg = get_fun_args(rip_expr)[0]
                if arg == self.info[('reg', tmp_base)]:
                    base, offset = self.stack.get_base_and_offset(arg)
                    ret_addr_expr = self.stack.read_item(base, offset)
                    if ret_addr_expr is not None and is_num(ret_addr_expr):
                        return get_num(ret_addr_expr)
        return None

    def _is_indirect_jump(self, rip_expr):
        # something like rip = LDle:I64(0x0000000000612fe0)
        # often for external calls
        if is_LDle(rip_expr):
            arg = get_fun_args(rip_expr)[0]
            if is_num(arg):
                size = get_LD_size(rip_expr)
                # TODO: ptr size
                return size == 64
        return False

    def get_next_insn_addr(self):
        """
        We do not handle complex conditions temporarily
        """
        next_b_id = None
        if ('reg', 'rip') in self.info.keys():
            ip_tree = self.info[('reg', 'rip')]
            if ip_tree.data == 'num':
                next_b_id = get_num(ip_tree)
            elif self.last_ijk_type == 'Ijk_Ret':
                next_b_id = self._get_return_type_rip_assignment(ip_tree)
                if next_b_id is None:
                    log.warning('ends with Return, but cannot find the return to address')
            else:
                log.warning('complex expression of rip = %s, cannot extend the trace.' % tree2str(ip_tree))
        else:
            log.warning('no value for rip, cannot extend the trace')
        return next_b_id

    def copy(self):
        tmp = Trace()
        tmp.constraints = deepcopy(self.constraints)
        tmp.info = deepcopy(self.info)
        tmp.stack = self.stack.copy()
        tmp.heap = self.heap.copy()
        tmp.blocks = self.blocks.copy()
        tmp.excall_seq = self.excall_seq.copy()
        # these could be None
        tmp.ip = self.ip
        tmp.stash = self.stash
        return tmp

    @staticmethod
    def constraints2str(constraints: list, handlers=None):
        if len(constraints) == 0:
            return 'true'
        elif len(constraints) == 1:
            return tree2str(constraints[0], handlers)
        else:
            already_has = set()
            # sometimes, constraints could repeat
            cs_strs = []
            for c in constraints:
                tmp_str = tree2str(c, handlers)
                if tmp_str in already_has:
                    continue
                already_has.add(tmp_str)
                cs_strs.append(tmp_str)
            if len(cs_strs) == 1:
                return cs_strs[0]
            res = 'And ( ' + cs_strs[0]
            for c_str in cs_strs[1:]:
                res += ' , ' + c_str
            res += ')'
            return res

    def constraints_str(self):
        return self.constraints2str(self.constraints)

    def valid_constraints_str(self):
        """
        Here is a heuristic to handle with some optimization and obfuscation which will
        introduce additional new constraints
        Here is an example
        (real constraint)
        cmovz eax, 0x12345
        ...
        cmp eax, 0x12345
        jz loc_xxx
        The obvious constraint is eax == 0x12345, but it is a substitution for real constraint
        Something like `cmovxx` will insert `If(c, a, b)` vex IR, if there is if in the constraints, we simply select
        the `c (constraint arg)`
        """

        def to_be_handled_If(t: Tree):
            if t.data == 'fun':
                args = get_fun_args(t)
                if is_If_fun(args[0]):
                    return True
            return False

        def handle_If_in_constraint(t: Tree, hs):
            args = get_fun_args(t)
            args = get_fun_args(args[0])
            # merely treat the constraints in If as valid part
            return tree2str(args[0], hs)

        handlers = [(to_be_handled_If, handle_If_in_constraint)]
        return self.constraints2str(self.constraints, handlers)

    def __str__(self):
        res = '%d blocks %s\n' % (len(self.blocks), str(self.id))
        res += 'external calls: ' + str(self.excall_seq) + '\n'
        # res += 'constraints: ' + self.constraints2str(self.constraints) + '\n'
        res += 'constraints: ' + self.valid_constraints_str() + '\n'
        for left, right in self.info.items():
            res += '  ' + str(left) + ' := ' + tree2str(right) + '\n'
        res += 'stack:\n'
        res += str(self.stack)
        res += 'heap:\n'
        res += str(self.heap)
        res += '\n'
        return res

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def normalize_a_tree(t, expr_bitvec_map: dict):
        """
        something like Get:I64(rax) will be replaced by bitvec_rax
        This process will modify the input tree
        """
        if not isinstance(t, Tree):
            return t
        if t.data == 'var':
            return t
        elif is_LDle(t):
            tmp_str = str(t)
            if tmp_str in expr_bitvec_map:
                return expr_bitvec_map[tmp_str]
            else:
                expr_bitvec_map[tmp_str] = create_BV_with_LD(t)
                return expr_bitvec_map[tmp_str]
        # elif is_GetI(t):
        # TODO: ...
        elif is_GET_reg(t):
            tmp_str = str(t)
            if tmp_str in expr_bitvec_map:
                return expr_bitvec_map[tmp_str]
            else:
                expr_bitvec_map[tmp_str] = create_BV_with_GET(t)
                return expr_bitvec_map[tmp_str]
        else:
            new_children = [Trace.normalize_a_tree(c, expr_bitvec_map) for c in t.children]
            t.children = new_children
        return t

    def normalize(self):
        """
        After being normalized, the trace cannot be extended later
        To normalize a trace, all loading-from-memory / reading-from-register operations are treated as symbolized
        bitvec
        """
        if self.normalized:
            # it has been normalized
            return
        set_g_BV_index(1)
        expr_bv_map = dict()
        # constraints
        new_constraints = [Trace.normalize_a_tree(cons, expr_bv_map) for cons in self.constraints]

        # info
        new_info = dict()
        for left_info, right_tree in self.info.items():
            new_info[left_info] = Trace.normalize_a_tree(right_tree, expr_bv_map)

        # stack
        new_ss = dict()
        for base in self.stack.ss.keys():
            new_ss[base] = dict()
            for offset, t in self.stack.ss[base].items():
                new_ss[base][offset] = Trace.normalize_a_tree(t, expr_bv_map)

        # heap
        new_mem = dict()
        for addr, t in self.heap.mem.items():
            new_mem[addr] = Trace.normalize_a_tree(t, expr_bv_map)

        self.constraints = new_constraints
        self.info = new_info
        self.stack.ss = new_ss
        self.heap.mem = new_mem
        self.normalized = True

    def is_sat(self):
        assert self.normalized, 'We only handle with normalized trace'
        for c in self.constraints:
            if is_num(c) and get_num(c) == 0:
                return False
            elif is_Not_fun(c):
                arg = get_fun_args(c)[0]
                if is_num(arg) and get_num(arg) == 1:
                    # Not(1)
                    return False
        # we do not use solver but simply infer it now
        return True


def merge_2_traces(t0: Trace, t1: Trace) -> Trace:
    """
    This function merge 2 traces to a trace
    t0 is executed just before t1
    """
    assert not (t0.normalized or t1.normalized)
    # the beginning state is t0, then add assignments of t1
    # Note: while iterating assignments of t1, the state of t0 should not be changed
    # update constraints
    new_constraints = deepcopy(t0.constraints)
    for t1_cons in t1.constraints:
        new_constraints.append(naive_hard_simplify(t0.replace_var_with_info(t1_cons)))

    # update info
    new_info = deepcopy(t0.info)
    for left_info, right_tree in t1.info.items():
        new_info[left_info] = naive_hard_simplify(t0.replace_var_with_info(right_tree))
    # some assignment in info may be moved to heap and stack

    # update heap
    new_mem = deepcopy(t0.heap.mem)
    for offset, t1_expr in t1.heap.mem.items():
        new_mem[offset] = naive_hard_simplify(t0.replace_var_with_info(t1_expr))

    # update stack
    new_ss = deepcopy(t0.stack.ss)
    for base in t1.stack.ss.keys():
        # the base register could be modified in t0, then the offset should also be changed
        new_base, bias = base, 0
        if ('reg', base) in t0.info.keys():
            t0_base, t0_offset = SymbolicStack.get_base_and_offset(t0.info[('reg', base)])
            if t0_offset is None:
                # the format is not able to be handled
                # TODO: we simply discard these info temporarily
                continue
            elif t0_base is None:
                # this should be put into heap
                for t1_offset, t1_expr in t1.stack.ss[base].items():
                    new_mem[t1_offset + t0_offset] = naive_hard_simplify(t0.replace_var_with_info(t1_expr))
                continue
            else:
                new_base = t0_base
                bias = t0_offset
        tmp_ss = dict()
        for t1_offset, t1_expr in t1.stack.ss[base].items():
            tmp_ss[t1_offset + bias] = naive_hard_simplify(t0.replace_var_with_info(t1_expr))
        if new_base not in new_ss.keys():
            new_ss[new_base] = dict()
        new_ss[new_base].update(tmp_ss)

    ret = Trace()
    ret.constraints = new_constraints
    ret.info = new_info
    ret.stack.ss = new_ss
    ret.heap.mem = new_mem
    ret.set_blocks(t0.blocks + t1.blocks)
    ret.set_ip(t1.ip)
    ret.set_stash(t1.stash)

    # move proper assignments in new_info to stack and heap
    move_to_mem_tmp = []
    for left_info, right_tree in ret.info.items():
        if left_info[0] == 'tmp':
            try:
                ret.save_into_memory(right_tree, ret.info[('deref', left_info[1])])
                move_to_mem_tmp.append(left_info[1])
            except UnrecognizableAddressExpressionException as e:
                log.info(str(e))
    for tmp_var in move_to_mem_tmp:
        ret.info.pop(('tmp', tmp_var))
        ret.info.pop(('deref', tmp_var))

    ret.set_last_ijk_type(t1.last_ijk_type)

    return ret


class TraceletsGraph:

    def __init__(self):
        self._starting_node_id = None
        self._tracelets = dict()
        self._succ_relations = dict()
        self._graph = nx.DiGraph()
        self._inlined_graph = None
        self.end_in_callee = set()

    @property
    def DG(self):
        return self._graph

    @property
    def inlined_DG(self):
        return self._inlined_graph

    def set_tracelets(self, tracelets):
        """
        this will clear existing tracelets
        """
        self._tracelets = dict()
        self._graph.clear()
        if isinstance(tracelets, list):
            for t in tracelets:
                self._tracelets[t.id] = t
        elif isinstance(tracelets, dict):
            self._tracelets = tracelets.copy()
        else:
            raise NotImplementedError()

    def set_succ_relations(self, r):
        self._succ_relations = r

    def get_tracelet(self, nid):
        return self._tracelets[nid]

    def find_tracelets_startswith(self, starts):
        if isinstance(starts, int):
            starts = (starts,)
        n = len(starts)
        ret = []
        for t_id in self._tracelets:
            if t_id[:n] == starts:
                ret.append(t_id)
        return ret

    @staticmethod
    def t1_is_direct_parent(t1_id, t2_id):
        if t2_id[0] in t1_id and t2_id != t1_id:
            tmp_idx = t1_id.index(t2_id[0])
            tmp_common_len = len(t1_id) - tmp_idx
            return t1_id[tmp_idx:] == t2_id[:tmp_common_len]
        return False

    def find_tracelet_direct_parent(self, t: Trace):
        parents = []
        for t_id in self._tracelets:
            if self.t1_is_direct_parent(t_id, t.id):
                if len(parents) == 0:
                    parents.append(t_id)
                    continue
                # we need filter redundant parents
                # if a, b are parents, and b is a's parent, then b could be removed
                tmp_new_ps = []
                for p_id in parents:
                    if self.t1_is_direct_parent(p_id, t_id):
                        # note we add p_id one by one, so there could not be 2 p_ids have parents relationships
                        # p_id is parent of t_id
                        # then replace p_id with t_id
                        tmp_new_ps.append(t_id)
                    else:
                        tmp_new_ps.append(p_id)
                parents = tmp_new_ps
        return parents

    def find_tracelet_direct_successors(self, t: Trace):
        successors = []
        if t.stash == 'active':
            successors = self.find_tracelets_startswith(t.ip)
        # for t_id in self._tracelets:
        #     if self.t1_is_direct_parent(t.id, t_id):
        #         if len(successors) == 0:
        #             successors.append(t_id)
        #             continue
        #         t_id_succ_already = set()
        #         t_id_is_a_succ_child = False
        #         for s_id in successors:
        #             if self.t1_is_direct_parent(t_id, s_id):
        #                 # t_id is s_id's parent, and t.id is t_id's parent, we preserve t_id but remove s_id
        #                 t_id_succ_already.add(s_id)
        #             elif self.t1_is_direct_parent(s_id, t_id):
        #                 t_id_is_a_succ_child = True
        #                 break
        #         if t_id_is_a_succ_child:
        #             # we do not insert t_id if its parent is in successors
        #             continue
        #         # add t_id and remove its children
        #         new_tmp_succs = [t_id]
        #         for s_id in successors:
        #             if s_id in t_id_succ_already:
        #                 continue
        #             new_tmp_succs.append(s_id)
        #         successors = new_tmp_succs
        return successors

    def build_main_DG(self, starting_node_id):
        assert len(self._tracelets) > 0
        # add all tracelets as nodes
        for t_id in self._tracelets:
            self._graph.add_node(t_id)
        # 0 is the entry node, which connects to the starting tracelets
        self._graph.add_node(0)

        to_find_succs = self.find_tracelets_startswith(starting_node_id)
        assert len(to_find_succs) > 0, 'the given starting node is incorrect'
        for t_id in to_find_succs:
            self._graph.add_edge(0, t_id)

        for pre_id in self._succ_relations.keys():
            assert pre_id in self._graph.nodes, 'wrong relation of %x, tracelet_id = %s' % (starting_node_id, pre_id)
            suc_head, suc_type = self._succ_relations[pre_id]
            if suc_type == 'ret':
                self.end_in_callee.add(pre_id)
            for succ_id in self.find_tracelets_startswith(suc_head):
                self._graph.add_edge(pre_id, succ_id)

    def build_isolated_nodes_connections(self, p: angr.Project, func_insns: list):
        """
        After building the main graph, there could be some nodes with no degree.
        The reason could be limitation of symbolic engine or simply unreachable code
        """
        pass

    def draw(self):
        nx.draw(self._graph)

    def append_graph(self, t_id, g):
        for tmp_t_id, tmp_t in g._tracelets.items():
            if tmp_t_id in self._tracelets:
                continue
            self._tracelets[tmp_t_id] = tmp_t
            self._inlined_graph.add_node(tmp_t_id)
        for e in g.DG.edges:
            if e[0] == 0:
                self._inlined_graph.add_edge(t_id, e[1])
            else:
                self._inlined_graph.add_edge(e[0], e[1])

    def build_inlined_DG(self, p: angr.Project, all_graphs: dict, inline_depth=3, nodes_upper_limit=2000):
        """
        This function inline the callee's graph into the whole graph
        """
        self._inlined_graph = self._graph.copy()
        if len(self._tracelets) >= nodes_upper_limit:
            return
        already_visited = set()
        for _ in range(inline_depth):
            to_be_appended = []
            for t_id, t in self._tracelets.items():
                if t_id in already_visited:
                    continue
                already_visited.add(t_id)
                if t.stash == 'active':
                    # find the trace starts with the call block and ends out side the function
                    # this means the callee's size beyouds the ability of tracelet length
                    bb = p.factory.block(addr=t_id[0])
                    if bb.capstone.insns[-1].insn.mnemonic.startswith('call'):
                        # this is a call block, the next block must go into the callee
                        if len(t_id) < 2:
                            # if not return, something wrong. Ignore it now.
                            continue
                        callee_entry = t_id[1]
                        if callee_entry in all_graphs:
                            # append the graph of callee to this tracelet
                            # cannot do this while iterating tracelets
                            to_be_appended.append((t_id, callee_entry))
            for t_id, callee_entry in to_be_appended:
                self.append_graph(t_id, all_graphs[callee_entry])
                if len(self._tracelets) >= nodes_upper_limit:
                    # stop inlining
                    return

