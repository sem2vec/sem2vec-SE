"""
The usage of pyvex is a bit strange, I just read the output of block.vex.pp() and analyze it.
t4 = GET:I64(rdi) will become t4 = GET:I64(offset=72)
I do not know what offset=72 is...
"""

import re

from lark import *

_IMark_re = re.compile(r"------ IMark\(.*, .*, .*\) ------")
_AbiHint_re = re.compile(r"====== AbiHint\(.*, .*, .*\) ======")
_Dirty_re = re.compile(r"DIRTY [0-9]+ TODO\(effects\)")


def get_insn_addr_from_IMark(s: str):
    tmp = s.split('IMark(')
    tmp = tmp[1].split(') ------')[0]
    addr_str = tmp.split(', ')[0]
    return int(addr_str, 16)


# _vex_func_map = {
#     "GET:I64": "__GET__I64",
#     "GET:I32": "__GET__I32",
#     "GET:I16": "__GET__I16",
#     "GET:I8": "__GET__I8",
#     "GET:I1": "__GET__I1",
#
#     "LDle:I64": "__LDle__I64",
#     "LDle:I32": "__LDle__I32",
#     "LDle:I16": "__LDle__I16",
#     "LDle:I8": "__LDle__I8",
#     "LDle:I1": "__LDle__I1",
#
#     "LDle:V128": "__LDle__V128",
#
#     "64to32": "__64to32",
#     "64to16": "__64to16",
#     "64to8": "__64to8",
#     "64to1": "__64to1",
#     "32to16": "__32to16",
#     "32to8": "__32to8",
#     "32to1": "__32to1",
#     "16to8": "__16to8",
#     "16to1": "__16to1",
#     "8to1": "__8to1",
#
#     "32Uto64": "__32Uto64",
#     "16Uto64": "__16Uto64",
#     "8Uto64": "__8Uto64",
#     "1Uto64": "__1Uto64",
#     "16Uto32": "__16Uto32",
#     "8Uto32": "__8Uto32",
#     "1Uto32": "__1Uto32",
#     "8Uto16": "__8Uto16",
#     "1Uto16": "__1Uto16",
#     "1Uto8": "__1Uto8",
#
#     "32Sto64": "__32Uto64",
#     "16Sto64": "__16Uto64",
#     "8Sto64": "__8Uto64",
#     "1Sto64": "__1Uto64",
#     "16Sto32": "__16Uto32",
#     "8Sto32": "__8Uto32",
#     "1Sto32": "__1Uto32",
#     "8Sto16": "__8Uto16",
#     "1Sto16": "__1Uto16",
#     "1Sto8": "__1Uto8",
# }


def read_IRSBs(path):
    irsbs = []
    with open(path, 'r') as f:
        lines = f.readlines()
        in_block = False
        block_id = None
        line_idx = 0
        block = []
        for line in lines:
            line = line.strip()
            if line.startswith('IRSB {'):
                block_id = int(line[7:], 16)
                in_block = True
            if line.startswith('}'):
                in_block = False

            if in_block:
                line_idx += 1
                if line_idx <= 3:
                    continue
                block.append(line)
            else:
                irsbs.append((block_id, block))
                block = []
                block_id = None
                line_idx = 0
    return irsbs


def vex_block_to_statements(lines):
    ret = dict()
    insn_addr = None
    for line in lines:
        if len(line) == 0 or _AbiHint_re.search(line) or _Dirty_re.search(line):
            continue
        if _IMark_re.search(line):
            insn_addr = get_insn_addr_from_IMark(line.strip())
            ret[insn_addr] = []
            continue
        # for fname in _vex_func_map.keys():
        #     if fname + '(' in line:
        #         line = line.replace(fname + '(', _vex_func_map[fname] + '(')
        if line.startswith("NEXT: "):
            ret[insn_addr].append(line[6:])
        else:
            ret[insn_addr].append(line[5:])
    ret = list(ret.items())
    ret = sorted(ret, key=lambda i: i[0])
    return ret


vex_grammar = r"""
stmt: assign_expr (";" atom)? | if

var: NAME
num: DEC_NUMBER | HEX_NUMBER | BIN_NUMBER | OCT_NUMBER | FLOAT_NUMBER | IMAG_NUMBER

fname: NAME | _bits_to | _bits_uto | _bits_sto | _bits_hito | _bits_hlto | _bits_utov | _bits_hltov | _with_ns
!_bits_to: num "to" num
!_bits_uto: num "Uto" num
!_bits_sto: num "Sto" num
!_bits_hito: num "HIto" num
!_bits_hlto: num "HLto" num
!_bits_utov: num "UtoV" num
!_bits_hltov: num "HLtoV" num
!_with_ns: NAME ":" NAME
args: atom? ("," atom)*
?fun: fname "(" [args] [num ":" atom] ")" [":" atom] ["[" atom "," atom "]"]

?atom: var | num
?if:  "if" "(" atom? ")" "{" stmt "}" ["else" "{" stmt "}"]

assign_expr: test "=" test
?test: or_test | fun
?or_test: and_test ("||" and_test)*
?and_test: not_test ("&&" not_test)*
?not_test: "!" not_test
         | comparison

?comparison: expr (_comp_op expr)*
?expr: xor_expr ("|" xor_expr)*
?xor_expr: and_expr ("^" and_expr)*
?and_expr: shift_expr ("&" shift_expr)*
?shift_expr: arith_expr (_shift_op arith_expr)*
?arith_expr: term (_add_op term)*
?term: factor (_mul_op factor)*
?factor: _factor_op factor | atom

!_factor_op: "+"|"-"|"~"
!_add_op: "+"|"-"
!_shift_op: "<<"|">>"
!_mul_op: "*"|"@"|"/"|"%"|"//"
!_comp_op: "<"|">"|"=="|">="|"<="|"<>"|"!="

%import python.NAME
%import python (DEC_NUMBER, HEX_NUMBER, OCT_NUMBER, BIN_NUMBER, FLOAT_NUMBER, IMAG_NUMBER)
%import common.WS

%ignore WS
"""

parser = Lark(vex_grammar, start="stmt", parser="lalr")


if __name__ == '__main__':
    irsbs = read_IRSBs('./test.IRSBs')
    for irsb in irsbs:
        res = vex_block_to_statements(irsb[1])
        for l in res:
            print(l[0])
            for s in l[1]:
                t = parser.parse(s)
                print(t.pretty())
