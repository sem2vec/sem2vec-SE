#!/bin/bash

dir_path="./samples/coreutils"

NORMAL='clang-4.0_-g_-O0  clang-4.0_-g_-O2  clang-4.0_-g_-O3  gcc-7.5_-g_-O0  gcc-7.5_-g_-O2  gcc-7.5_-g_-O3'
OBFS3="ollvm-O3-sub ollvm-O3-bcf ollvm-O3-fla ollvm-O3-sub-bcf-fla"

py="python3"
ver=`$py ./main.py --version`
echo "version is $ver"

run() {
    setting=$1
    max_state=$2
    angrdir=$3
    bin_path="$dir_path/$setting/coreutils"
    opts="--process 30 --timeout 1800 --max_state $max_state --angrdir $angrdir"
    if [[ $setting == *"-fla"* ]]; then
        opts="$opts --is-flatten"
    fi
    echo "setting = $setting"
    echo "max_state = $max_state"
    echo "$py ./main.py $bin_path $opts 2> $bin_path.err.log > $bin_path.out.log"
    eval "$py ./main.py $bin_path $opts 2> $bin_path.err.log > $bin_path.out.log"
}

settings="$NORMAL"

for max_state in 8
do
    for setting in $settings
    do
        angrdir_postfix="angr$ver--maxstate=$max_state.pkl"
        run $setting $max_state $angrdir_postfix
    done
done
wait

