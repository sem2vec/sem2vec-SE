from src.angr_full_blocks import *
from src.already_had import get_already_had_in_other_binaries
from config import args

if __name__ == '__main__':
    print(args)
    bin_path = args.bin_path[0]
    if args.others is not None and len(args.others) > 0:
        skip_fnames = get_already_had_in_other_binaries(bin_path, args.others)
    else:
        skip_fnames = None
    assert args.process > 0
    if args.process == 1:
        get_all_tracelets(bin_path, skip_exists=args.skip_exists)
    else:
        get_all_tracelets_multiprocess(bin_path, skip_exists=args.skip_exists, skip_fnames=skip_fnames)
