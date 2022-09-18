#!/bin/bash

py="python3"

all='addr2line  ar  as  c++filt  elfedit  gprof  ld  ld.bfd  nm  objcopy  objdump  ranlib  readelf  size  strings  strip'
dir_path='./samples/binutils'

settings='clang-4.0_-g_-O0  clang-4.0_-g_-O2  clang-4.0_-g_-O3  gcc-7.5_-g_-O0  gcc-7.5_-g_-O2  gcc-7.5_-g_-O3'

opts="--process 30 --skip-same-fnames --skip-exists --timeout 1800"
tmp_file=".tmp_multi_projs.log"

ver=`$py ./main.py --version`
echo "version is $ver"

run() {
    max_state=$1
    setting=$2
    angrdir=$3
    echo "max_state = $max_state"
    echo "setting = $setting"
    eval "rm $tmp_file"
    for bin in $all
    do
        bin_path="$dir_path/$setting/$bin"
        eval "echo $bin_path >> $tmp_file"
    done
    errfile="$dir_path/$setting/binutils.$max_state.err.log"
    outfile="$dir_path/$setting/binutils.$max_state.out.log"
    echo "$py main_multi_projs.py --bin_paths_txt $tmp_file $opts --max_state $max_state --angrdir $angrdir 2> $errfile > $outfile"
    eval "$py main_multi_projs.py --bin_paths_txt $tmp_file $opts --max_state $max_state --angrdir $angrdir 2> $errfile > $outfile"
}


for max_state in 8
do
    for setting in $settings
    do
        angrdir_postfix="angr$ver--maxstate=$max_state.pkl"
        run $max_state $setting $angrdir_postfix
    done
done
wait

