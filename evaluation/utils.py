import os
import pickle


def load_match_res_s(file_path):
    with open(file_path, 'r') as f:
        ret = dict()
        lines = f.readlines()
        for l in lines:
            tmp = l.split(' : ')
            ret[tmp[0]] = eval(tmp[1])
        return ret


def get_partial_valid_fname(fname):
    if '.' in fname:
        if fname[0] == '.':
            # it may be a lib function, consider about following part
            partial_name = fname[1:].split('.')[0]
            return '.' + partial_name
        else:
            return fname.split('.')[0]
    else:
        return fname

def compute_top_k_accuracy(match_res: dict, k: int, sort=True, fname_match_mode='simple'):
    """
    the match_res is a dictionary, with items of (fname, match_list)
    the elements in match_list is tuple of (fname, score)
    """
    assert k > 0
    if fname_match_mode == 'simple':
        all_valid_f1 = list(match_res.keys())
    else:
        all_valid_f1 = []

    in_top_k = []
    for f1, match_list in match_res.items():
        if not sort:
            match_list = list(sorted(match_list, key=lambda i: i[1], reverse=True))
        tmp = list(map(lambda i: i[0], match_list))
        if fname_match_mode == 'simple':
            if f1 in tmp[:k]:
                in_top_k.append(f1)
        elif fname_match_mode == 'fullyMatch':
            # the name of f1 must exist in match_list; otherwise, no result and we do not count
            if f1 in tmp:
                all_valid_f1.append(f1)
                if f1 in tmp[:k]:
                    in_top_k.append(f1)
        elif fname_match_mode == 'partialyMatch':
            # the valid f1 should be partialy matched with an item in match_list. For some functions such as 
            # `uptime.part.0`, the name `uptime` is the valid function name
            f1_partial = get_partial_valid_fname(f1)
            if f1_partial in tmp:
                all_valid_f1.append(f1)
                if f1_partial in tmp[:k]:
                    in_top_k.append(f1)
    if len(all_valid_f1) > 0: 
        return len(in_top_k) / len(all_valid_f1), in_top_k, all_valid_f1
    else:
        return 0.0, in_top_k, all_valid_f1
