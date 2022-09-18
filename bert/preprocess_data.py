from transformers import AutoTokenizer
from src.vex_tree_utils import *
import pickle
import random
import torch

tokenizer = AutoTokenizer.from_pretrained('bert-base-cased')


def preprocess_formulas(f1: Tree, f2: Tree, label: int, max_length, padding=True, return_tensor=True):
    tmp = tokenizer(tree2str(f1), tree2str(f2), padding=padding)
    n = max(max_length - len(tmp['input_ids']), 0)
    if return_tensor:
        return {'label': torch.tensor(label),
                'input_ids': torch.tensor(tmp['input_ids'] + [0 for _ in range(n)]),
                'attention_mask': torch.tensor(tmp['attention_mask'] + [0 for _ in range(n)])}
    else:
        return {'label': label,
                'input_ids': tmp['input_ids'] + [0 for _ in range(n)],
                'attention_mask': tmp['attention_mask'] + [0 for _ in range(n)]}


def preprocess_strings(s1: str, s2: str, label: int, max_length, padding=True, return_tensor=True):
    tmp = tokenizer(s1, s2, padding=padding)
    n = max(max_length - len(tmp['input_ids']), 0)
    if return_tensor:
        return {'label': torch.tensor(label),
                'input_ids': torch.tensor(tmp['input_ids'] + [0 for _ in range(n)]),
                'attention_mask': torch.tensor(tmp['attention_mask'] + [0 for _ in range(n)])}
    else:
        return {'label': label,
                'input_ids': tmp['input_ids'] + [0 for _ in range(n)],
                'attention_mask': tmp['attention_mask'] + [0 for _ in range(n)]}


def preprocess_a_same_line_pkl(pkl_path, max_token_len, padding=True, ratio=1, return_tensor=True):
    with open(pkl_path, 'rb') as f:
        r = pickle.load(f)
        res = []
        all_constraints = []
        # create relative constraints
        for _, two_traces in r.items():
            ts0, ts1 = two_traces
            ts0 = [t.constraints_str() for t in ts0]
            ts1 = [t.constraints_str() for t in ts1]
            all_constraints.extend(ts0)
            all_constraints.extend(ts1)
            n = min(len(ts0), len(ts1)) // 2 + 1
            for _ in range(n):
                cs0 = random.sample(ts0, k=1)[0]
                cs1 = random.sample(ts1, k=1)[0]
                # for completely same constraints, they must be similar
                # we do not skip them since some similar constraints with different sources
                # add these constraints to give strong bias for training
                #if cs0 == cs1:
                #    continue

                # we could ensure the order of formulas origin
                if random.random() < 0.5:
                    _tmp = preprocess_strings(cs0, cs1, 1, max_token_len, padding=padding, return_tensor=return_tensor)
                else:
                    _tmp = preprocess_strings(cs1, cs0, 1, max_token_len, padding=padding, return_tensor=return_tensor)
                if len(_tmp['input_ids']) > max_token_len:
                    continue
                res.append(_tmp)
        num_relative = len(res)
        # create irrelative constraints
        for _ in range(int(ratio * num_relative)):
            tmp = random.sample(all_constraints, k=2)
            if tmp[0] == tmp[1]:
                continue
            _tmp = preprocess_strings(tmp[0], tmp[1], 0, max_token_len, padding=padding, return_tensor=return_tensor)
            if len(_tmp['input_ids']) > max_token_len:
                continue
            res.append(_tmp)
        random.shuffle(res)
        return res
