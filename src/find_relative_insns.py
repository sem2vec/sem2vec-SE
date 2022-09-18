"""
This file read the output json file of asm_line_dict.sh to find all relative instructions
This is an effective way to get signature

However, it is no possible to get the corresponding signature in the target binary
The most assumption of target binary is function entries, then nothing.

We could use this to find equivalent assembly code blocks from 2 binaries, so that we could build enough
expression formulas for training

pyvex will convert each x86_64 instruction into a list of VEX IR instructions
so that we could build VEX IR lists of same source code with different compilation settings
"""
import json
import os
import sys
import pickle
import subprocess

from get_vex_IRSBs import get_block_irsb_raw_str
from src.analyze_irsb import analyze_a_block, vex_block_to_statements
from src.utils import *
from src.vex_parser import read_IRSBs


cache_opened_src_files = dict()


def read_an_IRSB(irsb_str):
    lines = irsb_str.split('\n')
    in_block = False
    block_id = None
    line_idx = 0
    block = []
    for line in lines:
        line = line.strip()
        if line.startswith('IRSB {'):
            block_id = int(line[7:], 16)
            in_block = True
        if line.startswith('}'):
            in_block = False

        if in_block:
            line_idx += 1
            if line_idx <= 3:
                continue
            block.append(line)
        else:
            return block


def load_bin_json(file_path):
    with open(file_path, 'r') as f:
        asm_line_map = json.load(f)
        updated_asm_line = dict()
        # build line_asm_map
        # a line could have multiple instructions, use an list ordered by assembly codes' addresses
        line_asm_map = dict()
        for asm_addr, line_info in asm_line_map.items():
            # line_info is a list with [file_name, line_num], use the tuple as the key
            key = tuple(line_info)
            if key not in line_asm_map:
                line_asm_map[key] = []
            asm_addr = int(asm_addr)
            line_asm_map[key].append(asm_addr)
            updated_asm_line[asm_addr] = tuple(line_info)
        for line in line_asm_map.keys():
            line_asm_map[line] = list(sorted(line_asm_map[line]))
        return updated_asm_line, line_asm_map


def get_asm_vex_map(raw_irsb_path):
    irsbs = read_IRSBs(raw_irsb_path)
    res = []
    for irsb in irsbs:
        stmts = vex_block_to_statements(irsb[1])  # the stmts is a list of (insn_addr, vex_list)
        res.extend(stmts)
    res = dict(res)
    return res


def get_asm_irsbEntry_map(raw_irsb_path):
    irsbs = read_IRSBs(raw_irsb_path)
    res = dict()
    for irsb in irsbs:
        stmts = vex_block_to_statements(irsb[1])  # the stmts is a list of (insn_addr, vex_list)
        tmp_entry = stmts[0][0]
        for s_addr, _ in stmts:
            res[s_addr] = tmp_entry
    return res


def get_file_lines(line_num, src_dir):
    tmp_file_name = line_num[0]
    if tmp_file_name in cache_opened_src_files:
        return cache_opened_src_files[tmp_file_name]
    cache_opened_src_files[tmp_file_name] = []
    while tmp_file_name.startswith('..'):
        tmp_file_name = tmp_file_name[3:]
    while tmp_file_name.startswith('./'):
        tmp_file_name = tmp_file_name[2:]
    src_file_path = os.path.join(src_dir, tmp_file_name)
    if not os.path.isfile(src_file_path):
        src_file_path = os.path.join(src_dir, 'lib', tmp_file_name)
    if not os.path.isfile(src_file_path):
        tmp = subprocess.check_output("find %s -name %s" % (src_dir, tmp_file_name), shell=True, encoding='utf-8')
        if len(tmp) != 0:
            src_file_path = tmp.split('\n')[0]
    with open(src_file_path) as f:
        cache_opened_src_files[tmp_file_name] = f.readlines()
    return cache_opened_src_files[tmp_file_name]


def get_line_str(line_num, src_dir):
    src_lines = get_file_lines(line_num, src_dir)
    if len(src_lines) < line_num[1]:
        return None
    src_line_str = src_lines[line_num[1] - 1]
    if src_line_str.endswith('\n'):
        src_line_str = src_line_str[:-1]
    # src_line_str = '>>> ' + src_line_str
    return src_line_str


def print_line(line_num, src_dir, ofile=sys.stdout):
    src_file_path = os.path.join(src_dir, line_num[0])
    with open(src_file_path) as f:
        print(str(line_num), file=ofile)
        src_lines = f.readlines()

        src_line_str = src_lines[line_num[1] - 1]
        if src_line_str.endswith('\n'):
            src_line_str = src_line_str[:-1]
        src_line_str = '>>> ' + src_line_str

        print(src_line_str, file=ofile)


def print_vex(asm_addr, asm_vex_map, ofile=sys.stdout):
    vex_irs = asm_vex_map[asm_addr + 0x400000]
    print('0x%x:' % asm_addr, file=ofile)
    for ir in vex_irs:
        print(ir, file=ofile)


def find_all_relative_insns(line_nums: list, line_asm_map: dict, versbos=0, source_code_dir=None):
    addrs = []
    for line_num in line_nums:
        addrs.extend(line_asm_map[line_num])
    return list(sorted(addrs))

