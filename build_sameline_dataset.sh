#!/bin/bash
py="python3"

bin1='./samples/test_same_lines/coreutils-gcc-O0'
bin2='./samples/test_same_lines/coreutils-gcc-O3'
src_code_dir='./samples/test_same_lines/coreutils-8.32'
dump_dir='./samples/test_same_lines/dump'

eval "bash ./scripts/asm_line_dict.sh $bin1"
eval "bash ./scripts/asm_line_dict.sh $bin2"

eval "$py ./scripts/get_vex_IRSBs.py $bin1"
eval "$py ./scripts/get_vex_IRSBs.py $bin2"

eval "$py ./get_traces_of_same_line_angr.py $bin1 $bin2 $src_code_dir $dump_dir"
eval "$py ./preprocess_angr_same_line.py $dump_dir"

