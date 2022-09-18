import sys
import re
import json

asm_has_line_re = re.compile("Line [0-9]+ of \".*\" starts at address 0x[0-9a-f]+")

f = open(sys.argv[1], 'r')
out_f = open(sys.argv[2], 'w')
lines = f.readlines()

res = dict()
for line in lines:
    line = line.strip()
    if line.startswith('(gdb) '):
        if asm_has_line_re.search(line[6:]):
            tmp = line[6:].split()
            code_line = int(tmp[1])
            src_file = tmp[3][1:-1]
            insn_addr = int(tmp[7], 16)
            res[insn_addr] = [src_file, code_line]

json.dump(res, out_f)
