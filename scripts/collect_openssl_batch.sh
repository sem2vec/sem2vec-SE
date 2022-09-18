#!/bin/bash
py="python3"

all='afalg.so  capi.so  libcrypto.so.1.1  libssl.so.1.1  openssl  padlock.so'

dir_path='./samples/openssl'

settings='gcc-O0 gcc-O2 gcc-O3 clang-O0 clang-O2 clang-O3'

opts="--process 30 --skip-same-fnames --skip-exists --timeout 1800"
tmp_file=".tmp_multi_projs.log"

ver=`$py ./main_angr.py --version`
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
    errfile="$dir_path/$setting/openssl.$max_state.err.log"
    outfile="$dir_path/$setting/openssl.$max_state.out.log"
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

