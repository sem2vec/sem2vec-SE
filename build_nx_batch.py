from config import args, VERSION
import logging
from nx_graphs.prepare_data import dump_bin_tracelets_graphs
import os


logging.getLogger('cle.loader').setLevel('ERROR')
logging.getLogger('cle.backends.externs').setLevel('ERROR')
logging.getLogger('SMP').setLevel('WARNING')

VER = VERSION


def build_func_graphs(bin_path):
    dump_dir_path = bin_path + f'.ecd{VER}.pkl'
    if not os.path.isdir(dump_dir_path):
        os.mkdir(dump_dir_path)
    dump_bin_tracelets_graphs(bin_path, dump_dir_path)


if __name__ == '__main__':
    print(args)
    assert args.process > 0
    bin_path_list = open(args.bin_paths_txt).readlines()
    bin_path_list = list(map(lambda l: l.strip(), bin_path_list))
    for bp in bin_path_list:
        print(bp)
        build_func_graphs(bp)
