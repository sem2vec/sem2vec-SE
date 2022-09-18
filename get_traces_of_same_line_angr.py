# -*- coding: utf-8 -*-
import sys
import os
import pickle
from src.find_relative_insns import *
from src.angr_full_blocks import *
from multiprocessing import Pool
from src.utils import *
import angr


def load_bin_data(bin_path):
    p = load_proj(bin_path)
    json_path = bin_path + '.json'
    insns_map_p = bin_path + '.insns.pkl'
    insns_map = pickle.load(open(insns_map_p, 'rb'))
    asm_line_map, line_asm_map = load_bin_json(json_path)
    return p, insns_map, asm_line_map, line_asm_map


def find_all_branch_src_code(line_asm_map, src_dir):
    ret = []
    for line_num in line_asm_map.keys():
        try:
            line_str = get_line_str(line_num, src_dir)
            if line_str is None:
                continue
            tmp = line_str.strip()
            if tmp.startswith('if') or tmp.startswith('for') or tmp.startswith('while') \
                    or (':' in tmp and '?' in tmp):
                ret.append(line_num)
        except FileNotFoundError as e:
            log.error(str(e) + ' not found ' + str(line_num))
        except IndexError as e:
            log.error(str(e) + ' reading from ' + str(line_num))
    return ret


def get_tracelets_multiprocess(start, p: angr.Project, sfe, dump_path, se_step=3,
                               state_limit=2000, valid_stashes=None):
    if valid_stashes is None:
        valid_stashes = ['active', 'unconstrained', 'deadended']
    traces = []
    tmp_state = create_blank_state(p, start, ['memaddr'])
    if len(tmp_state.block().instruction_addrs) == 0:
        return
    tmp_simgr = p.factory.simgr(tmp_state)
    try:
        with angr_symbolic_run_time_limit(6, tmp_state.addr):
            tmp_simgr.run(n=se_step)
    except Exception as e:
        return None
    for stash in valid_stashes:
        for s in tmp_simgr.stashes[stash]:
            traces.append(sfe.convert_angr_state_to_trace(s, tmp_state, stash))
    with open(dump_path, 'wb') as df:
        pickle.dump(traces, df)


def get_traces_pair(bin0_path, bin1_path, src_dir, dump_dir, processes=16):
    if not os.path.isdir(dump_dir):
        os.mkdir(dump_dir)
    tracelet_len = 3
    valid_stashes = ['active', 'unconstrained', 'deadended']
    state_limit = 16
    args_list = []
    bd0 = load_bin_data(bin0_path)
    offset0 = get_offset(bd0[0])
    bd1 = load_bin_data(bin1_path)
    offset1 = get_offset(bd1[0])
    valid_lines = find_all_branch_src_code(bd0[3], src_dir)
    folder_id = 0
    sfe0 = StateFormulaExtractor(bd0[0])
    sfe1 = StateFormulaExtractor(bd1[0])
    for line_num in valid_lines:
        if line_num not in bd1[3].keys():
            continue
        addr0 = bd0[3][line_num][0] + offset0
        # addr0 = bd0[4][addr0]
        addr1 = bd1[3][line_num][0] + offset1
        # addr1 = bd1[4][addr1]

        tmp_dump_dir = os.path.join(dump_dir, str(folder_id))
        if not os.path.isdir(tmp_dump_dir):
            os.mkdir(tmp_dump_dir)
        with open(os.path.join(tmp_dump_dir, 'line_num.txt'), 'w') as f:
            f.write(str(line_num) + '\n')
            f.write(str((bin0_path, '0x%x' % addr0)) + '\n')
            f.write(str((bin1_path, '0x%x' % addr1)) + '\n')
        args_list.append((addr0, bd0[0], sfe0, os.path.join(tmp_dump_dir, '0.pkl'), tracelet_len, state_limit))
        args_list.append((addr1, bd1[0], sfe1, os.path.join(tmp_dump_dir, '1.pkl'), tracelet_len, state_limit))
        folder_id += 1
    # dump all pair of tracelets on disk
    print('total number pf pairs %d' % (folder_id))
    pool = Pool(processes)
    pool.starmap(get_tracelets_multiprocess, args_list)


if __name__ == '__main__':
    p0 = sys.argv[1]
    p1 = sys.argv[2]
    src_dir_pa = sys.argv[3]
    dump_dir_pa = sys.argv[4]
    get_traces_pair(p0, p1, src_dir_pa, dump_dir_pa, processes=8)

