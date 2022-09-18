import torch
from torch.utils.data import Dataset
from torch.utils.data.dataset import T_co
from bert.preprocess_data import preprocess_a_same_line_pkl
import os
from multiprocessing import Pool, Manager


def _worker_for_each_pkl(pkl_path, max_tokens_len, queue):
    tmp = preprocess_a_same_line_pkl(pkl_path, max_tokens_len, return_tensor=False)
    queue.put(tmp)


def _to_tensor(i: dict):
    tmp = dict()
    for k, v in i.items():
        tmp[k] = torch.tensor(v)
    return tmp


class FormulaDataset(Dataset):

    def __init__(self, dir_path, max_tokens_len, processes=20):
        # super(self, FormulaDataset).__init__()
        self.data = []
        self.max_tokens_len = max_tokens_len
        self.processes = processes
        self.load_from_directory(dir_path)

    def __getitem__(self, index):
        return self.data[index]

    def __len__(self):
        return len(self.data)

    def load_from_directory(self, dir_path):
        pkl_files = os.listdir(dir_path)
        pkl_files = filter(lambda n: n.endswith('.pkl'), pkl_files)
        q = Manager().Queue()
        tmp_args = [(os.path.join(dir_path, pkl), self.max_tokens_len, q) for pkl in pkl_files]
        with Pool(self.processes) as pool:
            pool.starmap(_worker_for_each_pkl, tmp_args)
        while not q.empty():
            tmp = q.get()
            tmp = map(_to_tensor, tmp)
            self.data.extend(list(tmp))
        #for pkl in pkl_files:
        #    tmp = preprocess_a_same_line_pkl(os.path.join(dir_path, pkl), self.max_tokens_len)
        #    self.data.extend(tmp)

