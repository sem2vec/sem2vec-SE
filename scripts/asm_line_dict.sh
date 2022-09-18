#!/bin/bash

py="python3"
gdb="gdb"

bin=$1
bin_dump="$bin".dump
bin_gdbs="$bin".gdbs
bin_info="$bin".info
bin_json="$bin".json
eval "objdump -Dj .text $bin > $bin_dump"
eval "$py ./scripts/convert_dump_to_gdb_cmds.py $bin_dump $bin_gdbs"
eval "$gdb $bin < $bin_gdbs > $bin_info"
eval "$py ./scripts/build_insn_code_map.py $bin_info $bin_json"

eval "rm $bin_dump $bin_gdbs $bin_info"
