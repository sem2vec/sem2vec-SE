from src.function_traces import *
import sys

if __name__ == '__main__':
    bin_path = sys.argv[1]
    irsbs_pkl_path = get_IRSBs_pkl_path(bin_path)
    irsbs_pkl = pickle.load(open(irsbs_pkl_path, 'rb'))
    funcs = get_all_functions_of_bin_with_symbols(bin_path)
    func_traces_map = dict()
    for func_name, func_insns in funcs.items():
        func_entry, func_end = func_insns[-1] + 1
        if func_entry not in irsbs_pkl.keys():
            print('No IRSB of %s(0x%x)' % (func_name, func_entry))
            continue
        func_traces_map[func_name] = FunctionTraces(func_entry, func_end, bin_path, irsbs_pkl=irsbs_pkl)
    out_path = get_func_traces_pkl(bin_path)
    with open(out_path, 'wb') as f:
        pickle.dump(func_traces_map, f)
