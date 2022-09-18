import sys
import math, random
from tqdm import tqdm
from src.trace import Trace


formulas_set = set()

val_dist = {}

def process_a_formula_str(f_str):
    formula_tokens = f_str.split()
    if len(formula_tokens) < 5 or len(formula_tokens) > 286:
        return None

    for tok_idx in range(len(formula_tokens)):
        tok = formula_tokens[tok_idx]
        if "BV" in tok:
            #tmp = tok.split('_')
            #formula_tokens[tok_idx] = "bv" + tmp[1]
            formula_tokens[tok_idx] = "bv"
        elif "0x" in tok:
            value = int(tok, 16)
            if value == 0:
                formula_tokens[tok_idx] = "0"
            elif value <= 64:
                formula_tokens[tok_idx] = "constant " + str(value)
            else:
                formula_tokens[tok_idx] = "constant 2e"+str(int(math.log2(value)))
        elif "Reverse" in tok:
            formula_tokens[tok_idx] = "reverse"
        elif "Concat" in tok:
            formula_tokens[tok_idx] = "concat"
        elif "Extract" in tok:
            formula_tokens[tok_idx] = "extract"
        elif "SMod" in tok:
            formula_tokens[tok_idx] = "smod"
        elif "SDiv" in tok:
            formula_tokens[tok_idx] = "sdiv"
        elif "LShR" in tok:
            formula_tokens[tok_idx] = "lshr"
        elif "If" in tok:
            formula_tokens[tok_idx] = "if"
        elif "And" in tok:
            formula_tokens[tok_idx] = "and"
        elif "Or" in tok:
            formula_tokens[tok_idx] = "or"
        elif "Xor" in tok:
            formula_tokens[tok_idx] = "xor"
        elif "ULE" in tok:
            formula_tokens[tok_idx] = "ule"
        elif "SLE" in tok:
            formula_tokens[tok_idx] = "sle"
        elif "ULT" in tok:
            formula_tokens[tok_idx] = "ult"
        elif "SLT" in tok:
            formula_tokens[tok_idx] = "slt"
        elif "UGE" in tok:
            formula_tokens[tok_idx] = "uge"
        elif "SGE" in tok:
            formula_tokens[tok_idx] = "sge"
        elif "UGT" in tok:
            formula_tokens[tok_idx] = "ugt"
        elif "SGT" in tok:
            formula_tokens[tok_idx] = "sgt"
        elif "Not" in tok:
            formula_tokens[tok_idx] = "not"
        elif "SignExt" in tok:
            formula_tokens[tok_idx] = "signext"
        elif "ZeroExt" in tok:
            formula_tokens[tok_idx] = "zeroext"
        elif tok.count("__") == 2:
            op = tok[2:]
            end = op.index("__")
            formula_tokens[tok_idx] = op[:end]
        elif tok == "(" or tok == ")" or tok == ",":
            pass
        else:
            print(tok)
            raise NotImplementedError()
    return " ".join(formula_tokens)


def tracelet_to_formula_sentences(t: Trace, k=9):
    t_str = str(t)
    lines = t_str.split('\n')
    formula_sentences = []
    for l in lines[2:]:
        l = l.strip()
        if len(l) == 0:
            continue
        if l.startswith('stack') or l.startswith('heap'):
            continue
        if l.startswith('constraints:'):
            tmp_f_str = l.split(": ")[1]
            tmp_f = process_a_formula_str(tmp_f_str)
            if tmp_f is None:
                # give an empty constraints means always true
                tmp_f = ""
        else:
            tmp_f_str = l.split(":=")[1]
            tmp_f = process_a_formula_str(tmp_f_str)
            if tmp_f is None:
                continue
        formula_sentences.append(tmp_f)
    # the index 0 is constraint, reserve it
    # then select k longest remaining sentences
    # if no enough sentences, then left them empty
    # we feed to a RNN anyway, or we append all 0 vector later
    tmp = list(sorted(formula_sentences[1:], key=lambda s: len(s), reverse=True))[:k - 1]
    formula_sentences = [formula_sentences[0]] + tmp
    return formula_sentences


if __name__ == '__main__':
    raw_traces_file = sys.argv[1]
    with open(raw_traces_file) as raw_trace:
        for line in tqdm(raw_trace.readlines()):
            if ":=" not in line and 'constraints:' not in line:
                continue
            # if "0x" == line[:2]:continue
            if ":=" in line:
                rhs = line.split(":=")[1]
            else:
                rhs = line.split(": ")[1]
            tmp = process_a_formula_str(rhs)
            if tmp is None:
                continue
            formulas_set.add(tmp + "\n")

    data_size = len(formulas_set)
    print(data_size)
    formulas_list = list(formulas_set)
    random.shuffle(formulas_list)

    with open("data/train.txt", "w") as f:
        f.writelines(formulas_list[:int(data_size*0.9)])

    with open("data/test.txt", "w") as f:
        f.writelines(formulas_list[int(data_size*0.9):])
