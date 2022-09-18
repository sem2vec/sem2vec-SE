"""
This file collect useful traces of a function
and we use these traces as a signature of the function
"""

from src.utils import *
from src.vex_tree_utils import *
from src.trace import *
from src.analyze_irsb import extend_tracelet_to_length_n
import pickle
import os


def get_all_functions_of_bin_with_symbols(bin_path, offset=0x400000):
    tmp_dump_file = '%s.func.dump' % bin_path
    tmp_ret = os.system('objdump -Dj .text %s > %s' % (bin_path, tmp_dump_file))
    assert tmp_ret == 0
    functions = dict()
    in_func = False
    cur_func_name = None
    cur_func_start = None
    func_insn_addrs = None
    with open(tmp_dump_file) as f:
        lines = f.readlines()
        for line in lines:
            tmp = line.strip()
            if not in_func and tmp.endswith('>:'):
                in_func = True
                tmp = tmp.split()
                cur_func_start = int(tmp[0], 16) + offset
                cur_func_name = tmp[1][1:-2]
                func_insn_addrs = []
            elif in_func and len(tmp) == 0:
                in_func = False
                # not exactly the end, but 1 byte after last instruction
                functions[(cur_func_start, cur_func_name)] = func_insn_addrs
            elif in_func and len(tmp) > 0:
                # first split with \t
                # for normal instruction positions, the line format is `addr:`\t`bytes`\t`instructions`
                # for alignment cases, the line format is `addr:`\t`bytes`
                tmp = tmp.split('\t')
                if len(tmp) == 2:
                    continue
                try:
                    insn_addr = int(tmp[0][:-1], 16) + offset
                    func_insn_addrs.append(insn_addr)
                except Exception as e:
                    continue
    if in_func:
        functions[(cur_func_start, cur_func_name)] = func_insn_addrs
    # os.system('rm %s' % tmp_dump_file)
    return functions


def get_all_func_dump_section_offset(p, func_dump_path):
    if not p.loader.main_object.pic:
        return 0
    with open(func_dump_path) as f:
        line = f.readline().strip()
        assert line.endswith(':')
        tmp = line.split()
        sec_name = tmp[-1][:-1]
        return get_section(p, sec_name).min_addr


class FunctionTraces:

    def __init__(self, func_entry, func_end, bin_path, irsbs_pkl=None):
        self.entry = func_entry
        self.end = func_end
        self.bin_path = bin_path
        if irsbs_pkl is None:
            # load from disk
            self.block_traces_path = get_IRSBs_pkl_path(self.bin_path)
            with open(self.block_traces_path, 'rb') as f:
                self.irsbs_pkl = pickle.load(f)
        else:
            self.irsbs_pkl = irsbs_pkl
        self.valid_irsb_entries = self.get_all_valid_IRSBs()
        #self.beginning_traces = self.collect_beginning_traces()
        self.all_traces = self.collect_all_traces()

    def get_all_valid_IRSBs(self):
        valids = []
        for addr in self.irsbs_pkl.keys():
            if self.entry <= addr < self.end:
                valids.append(addr)
        return valids

    def collect_traces(self):
        pass

    def collect_beginning_traces(self, layers=3, trace_len_limit=4, trace_ext_num_limit=8):
        traces_layers = []
        cur_traces = self.irsbs_pkl[self.entry]
        for layer_idx in range(layers):
            next_traces_b_ids = [t.get_next_insn_addr() for t in cur_traces]
            tmp_e, tmp_n = extend_tracelet_to_length_n(cur_traces, self.irsbs_pkl, trace_len_limit, trace_ext_num_limit,
                                                       normalize=True)
            traces_layers.append(tmp_e + tmp_n)

            cur_traces = []
            for b_id in next_traces_b_ids:
                if b_id is None:
                    continue
                elif b_id not in self.irsbs_pkl.keys():
                    continue
                cur_traces.extend(self.irsbs_pkl[b_id])
        return traces_layers

    def collect_all_traces(self, trace_len_limit=3, trace_ext_num_limit=8):
        traces = dict()
        for entry in self.valid_irsb_entries:
            tmp_e, tmp_n = extend_tracelet_to_length_n(self.irsbs_pkl[entry], self.irsbs_pkl,
                                                       trace_len_limit, trace_ext_num_limit, normalize=True)
            if len(tmp_e) >= 2:
                traces[entry] = tmp_e + tmp_n
            else:
                traces[entry] = tmp_e + tmp_n
        return traces
