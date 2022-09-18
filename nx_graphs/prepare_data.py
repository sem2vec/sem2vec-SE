# -*- coding: utf-8 -*-

"""
prepare data for binary AI
"""
import pickle
import os
import sys
import random
from src.utils import log, get_angr_pkl_path, load_proj, get_offset
from src.trace import *
from src.function_traces import get_all_functions_of_bin_with_symbols, get_all_func_dump_section_offset
from bert.encoding_formulas import tracelet_to_encoding
import dgl
import torch
import networkx as nx

formula_vec_size = 768
formula_num = 1 + 9


def read_func_tracelets(pkl_path):
    with open(pkl_path, 'rb') as pf:
        try:
            return pickle.load(pf)
        except Exception as e:
            log.error('Error function\'s tracelets pkl %s' % pkl_path)
            return None, None


def build_graph_with_nodes_encoding(tg: TraceletsGraph, mode='normal'):
    orig_g = tg.inlined_DG if mode == 'inlined' else tg.DG
    dg = nx.DiGraph()
    replace_nid = dict()
    node_features = []
    node_excalls = []
    node_end_in_callee = []
    for node in orig_g.nodes:
        replace_nid[node] = len(replace_nid)
        if node == 0:
            # the starting node for the graph, unknown size, set all 0s later
            vec = [[0.0 for _ in range(formula_vec_size)]]
            excall = []
        else:
            tmp_tl = tg.get_tracelet(node)
            vec = tracelet_to_encoding(tmp_tl, formula_num)
            excall = tmp_tl.excall_seq
        node_features.append(vec)
        node_excalls.append(excall)
        node_end_in_callee.append(node in tg.end_in_callee)

    num_nodes = len(node_features)
    for n_id in range(num_nodes):
        dg.add_node(n_id, feat=node_features[n_id], excall=node_excalls[n_id], endincallee=node_end_in_callee[n_id])
    for u, v in orig_g.edges:
        dg.add_edge(replace_nid[u], replace_nid[v])
    return dg


def dump_a_tracelet_graphs(_from, _to, bin_path):
    func_pkl_path = _from
    tmp = os.path.basename(func_pkl_path).split('.')
    fid = (int(tmp[0], 16), '.'.join(tmp[1:-1]))
    tmp_dump_path = _to
    log.info('loading ' + func_pkl_path)
    func_tracelets, succ_relations = read_func_tracelets(func_pkl_path)
    if func_tracelets is None or len(func_tracelets) == 0:
        assert False
    tg = TraceletsGraph()
    tg.set_tracelets(func_tracelets)
    tg.set_succ_relations(succ_relations)
    log.info('building %s directed graph' % str(fid))
    tg.build_main_DG(fid[0])
    log.info('building %s directed graph with node encoding' % str(fid))
    tmp_g = build_graph_with_nodes_encoding(tg, mode='normal')
    log.info('dump ' + tmp_dump_path)
    with open(tmp_dump_path, 'wb') as df:
        pickle.dump(tmp_g, df)


def dump_bin_tracelets_graphs(bin_path, dump_dir):
    angr_pkl_dir = get_angr_pkl_path(bin_path)
    for func_pkl in os.listdir(angr_pkl_dir):
        func_pkl_path = os.path.join(angr_pkl_dir, func_pkl)
        tmp = func_pkl.split('.')
        fid = (int(tmp[0], 16), '.'.join(tmp[1:-1]))
        tmp_dump_path = os.path.join(dump_dir, func_pkl)
        # if os.path.isfile(tmp_dump_path):
        #     log.info('skip ' + func_pkl_path)
        #     continue
        log.info('loading ' + func_pkl_path)
        func_tracelets, succ_relations = read_func_tracelets(func_pkl_path)
        if func_tracelets is None or len(func_tracelets) == 0:
            continue
        tg = TraceletsGraph()
        tg.set_tracelets(func_tracelets)
        tg.set_succ_relations(succ_relations)
        log.info('building %s directed graph' % str(fid))
        tg.build_main_DG(fid[0])
        log.info('building %s directed graph with node encoding' % str(fid))
        tmp_g = build_graph_with_nodes_encoding(tg, mode='normal')
        tmp_dump_path = os.path.join(dump_dir, func_pkl)
        log.info('dump ' + tmp_dump_path)
        with open(tmp_dump_path, 'wb') as df:
            pickle.dump(tmp_g, df)


def dump_bin_tracelets_inlined_graphs(bin_path, dump_dir):
    angr_pkl_dir = get_angr_pkl_path(bin_path)
    p = load_proj(bin_path)
    all_graphs = dict()
    fids = dict()
    for func_pkl in os.listdir(angr_pkl_dir):
        func_pkl_path = os.path.join(angr_pkl_dir, func_pkl)
        tmp = func_pkl.split('.')
        fid = (int(tmp[0], 16), '.'.join(tmp[1:-1]))
        tmp_dump_path = os.path.join(dump_dir, func_pkl)
        if os.path.isfile(tmp_dump_path):
            log.info('skip ' + func_pkl_path)
            continue
        log.info('loading ' + func_pkl_path)
        func_tracelets, succ_relations = read_func_tracelets(func_pkl_path)
        if func_tracelets is None or len(func_tracelets) == 0:
            assert False
        tg = TraceletsGraph()
        tg.set_tracelets(func_tracelets)
        tg.set_succ_relations(succ_relations)
        log.info('building %s directed graph' % str(fid))
        tg.build_main_DG(fid[0])
        all_graphs[fid[0]] = tg
        fids[fid[0]] = (fid, func_pkl)

    log.info('start building inlined graph')
    for fentry, tg in all_graphs.items():
        fid, func_pkl = fids[fentry]
        orig_nodes = len(tg.DG.nodes)
        log.info('building %s inlined graph' % str(fid))
        tg.build_inlined_DG(p, all_graphs,
                            inline_depth=3,
                            nodes_upper_limit=100)
        inlined_nodes = len(tg.inlined_DG.nodes)
        log.info('%s %d -> %d' % (str(fid), orig_nodes, inlined_nodes))
        log.info('building %s directed graph with node encoding' % str(fid))
        tmp_g = build_graph_with_nodes_encoding(tg, mode='inlined')
        tmp_dump_path = os.path.join(dump_dir, func_pkl)
        log.info('dump ' + tmp_dump_path)
        with open(tmp_dump_path, 'wb') as df:
            pickle.dump(tmp_g, df)


class FuncMatchDataset(dgl.data.DGLDataset):

    def __init__(self, dir1, dir2, save_dir=None, force_reload=False, verbose=False):
        name = "%s_vs._%s" % (dir1, dir2)
        name = name.replace('/', '_')
        hash_key = (dir1, dir2)
        self._dirs = [dir1, dir2]
        self._gs = [dict() for _ in range(len(self._dirs))]
        self._basename_fid_map = [dict() for _ in range(len(self._dirs))]
        self._same_func = []
        self._diff_func = []
        self._glist = []
        self._label_list = []
        super(FuncMatchDataset, self).__init__(name, None, None, save_dir, hash_key, force_reload, verbose)

    @staticmethod
    def get_func_pkls(d):
        ret = dict()
        for pkl_name in os.listdir(d):
            tmp = pkl_name.split('.')
            func_addr = int(tmp[0], 16)
            func_base_name = tmp[1]
            func_full_name = '.'.join(tmp[1:-1])
            pkl_path = os.path.join(d, pkl_name)
            tmp_g = pickle.load(open(pkl_path, 'rb'))
            if len(tmp_g.ndata['feat']) < 6:
                continue
            ret[(func_addr, func_base_name, func_full_name)] = tmp_g
        return ret

    @staticmethod
    def build_func_basename_fid_map(graphs):
        ret = dict()
        for fid in graphs:
            addr, bn, fn = fid
            if bn not in ret:
                ret[bn] = []
            ret[bn].append(fid)
        return ret

    def create_same_source_function_graphs(self, fid):
        addr, bn, fn = fid
        ret = []
        ret_fids = []
        gs_idx = 0
        for gs in self._gs:
            if fid in gs:
                ret.append(gs[fid])
                ret_fids.append(fid)
            elif bn in self._basename_fid_map[gs_idx]:
                tmp_fid = random.sample(self._basename_fid_map[gs_idx][bn], k=1)[0]
                ret.append(gs[tmp_fid])
                ret_fids.append(tmp_fid)
            else:
                # no matched function
                return None, None
            gs_idx += 1
        return dgl.batch(graphs=ret), tuple(ret_fids)

    def __getitem__(self, idx):
        return dgl.add_self_loop(self._glist[idx]), self._label_list['glabel'][idx]

    def __len__(self):
        return len(self._glist)

    @property
    def num_classes(self):
        return 2

    def process(self):
        d1_fs = self.get_func_pkls(self._dirs[0])
        d2_fs = self.get_func_pkls(self._dirs[1])
        self._gs = [d1_fs, d2_fs]
        self._basename_fid_map = [self.build_func_basename_fid_map(fgs) for fgs in self._gs]
        # build graphs with same source functions
        for fid in self._gs[0]:
            tmp_g, tmp_fids = self.create_same_source_function_graphs(fid)
            if tmp_g is None:
                continue
            self._same_func.append((tmp_g, tmp_fids))

        # build graphs with different source functions
        n_diff = len(self._same_func)
        while len(self._diff_func) < n_diff:
            fid0, fg0 = random.sample(self._gs[0].items(), k=1)[0]
            fid1, fg1 = random.sample(self._gs[0].items(), k=1)[0]
            if fid0[1] == fid1[1]:
                # same function basename
                continue
            self._diff_func.append(dgl.batch([fg0, fg1]))

        tmp_graphs = []
        for g, fids in self._same_func:
            tmp_graphs.append((g, torch.tensor(1)))
        for g in self._diff_func:
            tmp_graphs.append((g, torch.tensor(0)))
        random.shuffle(tmp_graphs)
        self._glist = list(map(lambda i: i[0], tmp_graphs))
        self._label_list = {'glabel': torch.tensor(list(map(lambda i: i[1], tmp_graphs)))}

    def save(self):
        filename = os.path.join(self._save_dir, 'func_match_dataset.bin')
        dgl.data.graph_serialize.save_graphs(filename, self._glist, self._label_list)

    def load(self):
        filename = os.path.join(self._save_dir, 'func_match_dataset.bin')
        self._glist, self._label_list = dgl.data.graph_serialize.load_graphs(filename)
        print('load data from ' + filename)
        print('# of items: %d' % len(self._glist))

    def has_cache(self):
        filename = os.path.join(self._save_dir, 'func_match_dataset.bin')
        return os.path.isfile(filename)


class FuncMatchEvalDataset(dgl.data.DGLDataset):
    def __init__(self, dir1, dir2, force_reload=False, verbose=False):
        name = "%s_vs._%s" % (dir1, dir2)
        name = name.replace('/', '_')
        hash_key = (dir1, dir2)
        self._dirs = [dir1, dir2]
        self._gs = [dict() for _ in range(len(self._dirs))]
        super(FuncMatchEvalDataset, self).__init__(name, None, None, None, hash_key, force_reload, verbose)
        self._total_cmp_num = len(self._gs[0]) * len(self._gs[1])

    def load(self):
        self.process()

    def process(self):
        d1_fs = FuncMatchDataset.get_func_pkls(self._dirs[0])
        d2_fs = FuncMatchDataset.get_func_pkls(self._dirs[1])
        self._gs = [list(d1_fs.items()), list(d2_fs.items())]

    def __getitem__(self, idx):
        f0_idx = idx // len(self._gs[1])
        f1_idx = idx % len(self._gs[1])
        fid0, fg0 = self._gs[0][f0_idx]
        fid1, fg1 = self._gs[1][f1_idx]
        tmp_g = dgl.add_self_loop(dgl.batch([fg0, fg1]))
        if fid0[1] == fid1[1]:
            tmp_l = torch.tensor(1)
        else:
            tmp_l = torch.tensor(0)
        return tmp_g, tmp_l

    def get_cmp_fids(self, idx):
        f0_idx = idx // len(self._gs[1])
        f1_idx = idx % len(self._gs[1])
        fid0, fg0 = self._gs[0][f0_idx]
        fid1, fg1 = self._gs[1][f1_idx]
        return fid0, fid1

    def __len__(self):
        return len(self._gs[0]) * len(self._gs[1])

    @property
    def num_classes(self):
        return 2

    def has_cache(self):
        # the input of 2 directories are cached graph of functions to be matched
        return True
