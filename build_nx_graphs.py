# -*- coding: utf-8 -*-

from nx_graphs.prepare_data import dump_bin_tracelets_graphs, dump_bin_tracelets_inlined_graphs
import os
import sys
import pickle
from src.utils import log
from config import args, VERSION


log.setLevel('INFO')

VER = VERSION


def build_func_graphs():
    bin_path = sys.argv[1]
    dump_dir_path = bin_path + '.' + args.ecddir
    if not os.path.isdir(dump_dir_path):
        os.mkdir(dump_dir_path)
    dump_bin_tracelets_graphs(bin_path, dump_dir_path)


if __name__ == '__main__':
    build_func_graphs()

