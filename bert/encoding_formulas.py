# -*- coding: utf-8 -*-
from torch.utils.data import DataLoader
from sentence_transformers import SentenceTransformer, losses, models
from sentence_transformers.evaluation import EmbeddingSimilarityEvaluator
from sentence_transformers.readers import InputExample
import pickle
import math
import os
import sys
import numpy as np
from numpy import dot
from numpy.linalg import norm
from src.utils import *
from src.trace import Trace
from bert.preprocess import process_a_formula_str, tracelet_to_formula_sentences

model_path = "./bert/FoBERT2/checkpoint-70000"
model = SentenceTransformer("./bert/FoBERT2-SS")


def get_formulas_encodes(fs: list):
    return model.encode(fs)


def formulas_encodings_to_tracelet_encoding(e):
    # max pooling
    # return np.max(e, 0)
    # only constraints
    # return [e[0]]
    return e


tracelet_encoding_cache = dict()


def tracelet_to_encoding(t: Trace, k=9):
    if t.id in tracelet_encoding_cache:
        return tracelet_encoding_cache[t.id]
    fs = tracelet_to_formula_sentences(t, k=k)
    es = get_formulas_encodes(fs)
    e = formulas_encodings_to_tracelet_encoding(es)
    tracelet_encoding_cache[t.id] = e
    return e
