# -*- coding: utf-8 -*-
"""
This is only used for projects with same function across different binaries
"""


import os
import sys
from src.utils import *


def get_already_had_in_other_binaries(bin_path, others):
    """
    other binaries in the same project should in the same directory
    """
    all_fnames = set()
    d = os.path.dirname(bin_path)
    for ob in others:
        obp = os.path.join(d, ob)
        tmp_angr_pkl_dir = get_angr_pkl_path(obp)
        if os.path.isdir(tmp_angr_pkl_dir):
            tmp_pkls = os.listdir(tmp_angr_pkl_dir)
            tmp_fnames = set(map(lambda n: n.split('.')[1], tmp_pkls))
            all_fnames.update(tmp_fnames)
    all_fnames = all_fnames - {'main'}
    return all_fnames

