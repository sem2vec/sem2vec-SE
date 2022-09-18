# -*- coding: utf-8 -*-

import os
import sys
import pickle
import random
from bert.preprocess import process_a_formula_str


def read_a_pair(pkl_dir):
    pkl0 = os.path.join(pkl_dir, '0.pkl')
    pkl1 = os.path.join(pkl_dir, '1.pkl')
    if not os.path.isfile(pkl0) or not os.path.isfile(pkl1):
        return None
    tracelets0 = pickle.load(open(pkl0, 'rb'))
    tracelets1 = pickle.load(open(pkl1, 'rb'))
    if len(tracelets0) == 0 or len(tracelets1) == 0:
        return None
    n = max(len(tracelets0), len(tracelets1))
    ret = []
    for _ in range(n):
        c0 = random.sample(tracelets0, k=1)[0]
        c1 = random.sample(tracelets1, k=1)[0]
        if random.random() > 0.5:
            _c = c0
            c0 = c1
            c1 = _c
        c0 = process_a_formula_str(c0.constraints_str())
        c1 = process_a_formula_str(c1.constraints_str())
        if c0 is None or c1 is None:
            continue
        ret.append([c0, c1, True])
    return ret


if __name__ == '__main__':
    pkls_dir = sys.argv[1]
    pos_cases = []
    stdout_file_path = os.path.join(pkls_dir, 'stdout.log')
    stdout_f = open(stdout_file_path, 'w')
    for pkl_dir in os.listdir(pkls_dir):
        try:
            tmp = read_a_pair(os.path.join(pkls_dir, pkl_dir))
            if tmp is not None:
                for i in tmp:
                    print(str(i), file=stdout_f)
                pos_cases.extend(tmp)
        except Exception as e:
            print('err in ' + pkl_dir, file=sys.stderr)
    # create the same # of negative cases
    stdout_f.close()
    with open(stdout_file_path) as f:
        for line in f.readlines():
            pos_cases.append(eval(line))
    n = len(pos_cases)
    print('# positive cases %d' % n)
    neg_cases = []
    for _ in range(n):
        c0 = random.sample(pos_cases, k=1)[0][0]
        c1 = random.sample(pos_cases, k=1)[0][1]
        neg_cases.append([c0, c1, False])
    res = pos_cases + neg_cases
    random.shuffle(res)
    with open(pkls_dir + '.sameline.pkl', 'wb') as df:
        pickle.dump(res, df)


