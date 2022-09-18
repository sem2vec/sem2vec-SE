"""
This file implements the symbolic heap

A symbolic heap is similar (or same?) to the symbolic memory

We treat all operations on fixed addresses as reading from/writing into heap.
However, when it tries to read/write an symbolized address, we keep the symbolized addresses,
instead of concretizing them.
For example: ('tmp', t0) : rax;  ('def', t0) : 0x12345, this format will be kept until rax becomes a constant.

After merging with former blocks, the symbolized memory address is possible becoming a fixed value.
"""
import copy

from src.vex_tree_utils import Tree, tree2str


class SymbolicHeap:

    def __init__(self):
        self.mem = dict()

    def save_item(self, addr: int, value: Tree):
        self.mem[addr] = value

    def read_item(self, addr: int):
        if addr in self.mem:
            return self.mem[addr]
        else:
            return None

    def copy(self):
        sh = SymbolicHeap()
        sh.mem = copy.deepcopy(self.mem)
        return sh

    def __str__(self):
        res = ''
        for offset in self.mem.keys():
            res += '0x%x := ' % offset + tree2str(self.mem[offset]) + '\n'
        return res
