import pickle, os
import sys


dir_path = sys.argv[1]
dest_file = sys.argv[2]

with open(dest_file, "w") as dest:
    for idx, pkl_file in enumerate(os.listdir(dir_path)):
        print(idx)
        pkl_path = os.path.join(dir_path, pkl_file)
        if pkl_path.split(".")[-1] != "pkl":
            print(f"skip {pkl_path}")
            continue
        try:
            with open(pkl_path, "rb") as p:
                traces = pickle.load(p)
                for trace in traces:
                    dest.write(str(trace) + "\n")
        except EOFError:
            print(f"fail to process {pkl_path}")
