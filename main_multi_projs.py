from src.angr_full_blocks import *
from src.already_had import get_already_had_in_other_binaries
from config import args
import logging


logging.getLogger('cle.loader').setLevel('ERROR')
logging.getLogger('cle.backends.externs').setLevel('ERROR')
logging.getLogger('SMP').setLevel('INFO')


if __name__ == '__main__':
    print(args)
    assert args.process > 0
    bin_path_list = open(args.bin_paths_txt).readlines()
    bin_path_list = list(map(lambda l: l.strip(), bin_path_list))
    get_all_tracelets_multiprocess2(bin_path_list,
                                    skip_exists=args.skip_exists,
                                    skip_fnames=None,
                                    skip_same_fnames=args.skip_same_fnames)
