# -*- coding: utf-8 -*-

"""
This file has codes to get info of a basic block
The info should be able to pass to neighbor blocks to form a trace-let
"""


from src.utils import *
from src.state_plugins import *
from src.formula import FormulaNode
import claripy
import angr.sim_state

AMD64_REGS = {
    'rdi': 64,
    'rsi': 64,
    'rax': 64,
    'rbx': 64,
    'rcx': 64,
    'rdx': 64,
    'rbp': 64,
    'rsp': 64,
}

REGS = AMD64_REGS


def is_ptr_concretize_format_constraint(expr):
    return expr.symbolic and isinstance(expr, claripy.ast.bool.Bool) \
            and expr.depth == 2 and expr.op == '__eq__' \
            and (not expr.args[1].symbolic)


class BBInfo:

    def __init__(self, p: angr.Project, addr: int):
        """
        The project and the start RVA of this basic block
        """
        state = create_blank_state(p, addr, ['memaddr'])
        sucs = state.step()
        self.reg_fs, self.mem_fs, self.constraints = BBInfo.read_info_from_successors(sucs)

    @staticmethod
    def read_ptr_constraints(sucs):
        ptr_constraints = []
        # We first collect info from a state
        s = sucs.all_successors[0]
        for c in s.solver.constraints:
            if c.args[0] in s.memaddr.mem_ptr_symbols:
                # c is an redundant constraint for pointer concretization
                ptr_constraints.append(c)
                continue
        return ptr_constraints

    @staticmethod
    def read_transfer_constraints(sucs):
        all_tcs = []
        # collect transfer constraints on other successors
        for s in sucs.flat_successors:
            transfer_constraints = []
            for c in s.solver.constraints:
                if c.args[0] in s.memaddr.mem_ptr_symbols:
                    # c is an redundant constraint for pointer concretization
                    continue
                if c.symbolic:
                    # sometimes <Bool True> is also in it
                    transfer_constraints.append(c)
            all_tcs.append((transfer_constraints, s.addr))
        for s in sucs.unconstrained_successors:
            transfer_constraints = []
            for c in s.solver.constraints:
                if c.args[0] in s.memaddr.mem_ptr_symbols:
                    # c is an redundant constraint for pointer concretization
                    continue
                if c.symbolic:
                    # sometimes <Bool True> is also in it
                    transfer_constraints.append(c)
            all_tcs.append((transfer_constraints, None))
        return all_tcs

    @staticmethod
    def read_constraints(sucs: angr.engines.successors.SimSuccessors):
        return BBInfo.read_transfer_constraints(sucs), BBInfo.read_ptr_constraints(sucs)

    @staticmethod
    def read_all_expressions(sucs: angr.engines.successors.SimSuccessors):
        # the sucs must have at least 1 successor
        s = sucs.all_successors[0]
        # expression of all register
        exprs = dict()
        for reg_name in REGS.keys():
            exprs[reg_name] = getattr(s.regs, reg_name)
        # expression of all modified memory
        changed_mem_addr_set = s.memory.changed_bytes(sucs.initial_state.memory)
        # TODO: should we assume the returned addresses are sorted?
        changed_mem_addr_set = sorted(list(changed_mem_addr_set))
        mem_exprs = dict()
        visited_objs = set()
        for addr in changed_mem_addr_set:
            if s.memory.mem[addr] is None:
                continue
            if s.memory.mem[addr].object in visited_objs:
                continue
            mem_exprs[addr] = s.memory.mem[addr].object
            visited_objs.add(s.memory.mem[addr].object)
        return exprs, mem_exprs

    @staticmethod
    def rebuild_expressions_without_concretization(expr_dict, ptr_map, done_map={}):
        formula_dict = dict()
        for left_hand, e in expr_dict.items():
            f = FormulaNode.get_formula_tree(e)
            formula_dict[left_hand] = FormulaNode.rebuild_formula_without_concretization(f, ptr_map, done_map)
        return formula_dict

    @staticmethod
    def rebuild_memory_expressions_without_concretization(expr_dict, ptr_map, done_map={}):
        formula_dict = dict()
        for left_hand, e in expr_dict.items():
            f = FormulaNode.get_formula_tree(e)
            if left_hand in ptr_map:
                left_hand = ptr_map[left_hand][0]
            formula_dict[left_hand] = FormulaNode.rebuild_formula_without_concretization(f, ptr_map, done_map)
        return formula_dict

    @staticmethod
    def rebuild_an_expression_without_concretization(expr, ptr_map, done_map={}):
        f = FormulaNode.get_formula_tree(expr)
        return FormulaNode.rebuild_formula_without_concretization(f, ptr_map, done_map)

    @staticmethod
    def read_info_from_successors(sucs):
        if len(sucs.all_successors) == 0:
            raise Exception('angr failed to symbolic execute this block')
        real_constraints, ptr_constraints = BBInfo.read_constraints(sucs)
        reg_exprs, mem_exprs = BBInfo.read_all_expressions(sucs)
        # some pointers have been concretized while executing, we need to rebuild this info
        # to remove the influence of concretization
        # This process could be done directly on IR or assembly, so that we do not need to use symbolic engine.
        # This process could be faster
        ptr_map = FormulaNode.ptr_constraints_to_ptr_map(ptr_constraints)
        done_map = dict()
        reg_formulas = BBInfo.rebuild_expressions_without_concretization(reg_exprs, ptr_map, done_map)
        mem_formulas = BBInfo.rebuild_memory_expressions_without_concretization(mem_exprs, ptr_map, done_map)
        tmp_constraint = []
        for constraints, succ_addr in real_constraints:
            tmp = []
            for c in constraints:
                tmp.append(BBInfo.rebuild_an_expression_without_concretization(c, ptr_map, done_map))
            tmp_constraint.append((tmp, succ_addr))
        return reg_formulas, mem_formulas, tmp_constraint
