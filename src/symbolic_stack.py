"""
This file implements the symbolic stack

A symbolic stack is similar to the symbolic memory
but the original stack pointer is symbolized `rbp`

We treat all operations on addresses with `rbp +/- xxx` as reading from/writing into stack.

By symbolizing `rbp`, it is possible to merge infos from 2 basic blocks together
"""

import copy

from src.vex_tree_utils import *


class SymbolicStack:

    def __init__(self):
        """
        We use a dictionary with items (rbp_offset, value) to save values in this stack
        """
        self.ss = dict()

    def save_item(self, base, offset, value, value_size=0):
        """
        the `value` with `value_size` bytes will be saved in
        offset -- offset + (value_size - 1)
        ignore the value_size temporarily
        """
        if base not in self.ss:
            self.ss[base] = dict()
        self.ss[base][offset] = value

    def read_item(self, base, offset):
        if base in self.ss and offset in self.ss[base]:
            return self.ss[base][offset]
        else:
            return None

    def copy(self):
        tmp = SymbolicStack()
        tmp.ss = copy.deepcopy(self.ss)
        return tmp

    @staticmethod
    def get_base_and_offset(addr_formula: Tree):
        """
        The formula must be in the form of `Add64 ( GET:I64 ( rsp )  , 0x40 )` (or no add node)
        """
        if is_Add_fun(addr_formula):
            args = get_fun_args(addr_formula)
            if is_GET_reg(args[0]):
                base = GET_reg_name(args[0])
            else:
                return None, None
            if is_num(args[1]):
                offset = get_num(args[1])
                if 0xffffffffffffffff - offset + 1 < 0x1000:
                    offset = -(0xffffffffffffffff - offset + 1)
            else:
                return None, None
        elif is_Sub_fun(addr_formula):
            args = get_fun_args(addr_formula)
            if is_GET_reg(args[0]):
                base = GET_reg_name(args[0])
            else:
                return None, None
            if is_num(args[1]):
                offset = -get_num(args[1])
            else:
                return None, None
        elif is_GET_reg(addr_formula):
            base = GET_reg_name(addr_formula)
            offset = 0
        elif is_num(addr_formula):
            base = None
            offset = get_num(addr_formula)
        else:
            return None, None
        return base, offset

    @staticmethod
    def offset2str(offset):
        if offset >= 0:
            return '0x%x' % offset
        else:
            return '-0x%x' % (-offset)

    def __str__(self):
        res = ''
        for base in self.ss.keys():
            res += base + '\n'
            for offset in self.ss[base].keys():
                res += ' ' * 4 + '%s := ' % self.offset2str(offset) + tree2str(self.ss[base][offset]) + '\n'
        return res
