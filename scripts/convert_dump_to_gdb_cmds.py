# -*- coding: utf-8 -*-

import sys

f = open(sys.argv[1], 'r')
out_f = open(sys.argv[2], 'w')
lines = f.readlines()
f.close()

in_a_function = False
for line in lines:
    line = line.strip()
    if not in_a_function and line.endswith('>:'):
        in_a_function = True
    elif in_a_function:
        if len(line) == 0:
            in_a_function = False
        else:
            insn_addr = line.split()[0][:-1]
            out_f.write('info line *0x%s\n' % insn_addr)

out_f.close()
