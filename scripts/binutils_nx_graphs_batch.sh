#!/bin/bash
py="python3"

all='addr2line  ar  as  c++filt  elfedit  gprof  ld  ld.bfd  nm  objcopy  objdump  ranlib  readelf  size  strings  strip'
settings='clang-4.0_-g_-O0  clang-4.0_-g_-O2  clang-4.0_-g_-O3  gcc-7.5_-g_-O0  gcc-7.5_-g_-O2  gcc-7.5_-g_-O3'

ver=`$py ./main.py --version`
echo "version is $ver"

dir_path='./samples/binutils'


ecd_total() {
    max_state=$1
    setting=$2
    ecddir="ecd$ver--maxstate=$max_state.pkl"
    angrdir="angr$ver--maxstate=$max_state.pkl"
    echo "max_state = $max_state"
    echo "setting = $setting"
    errfile="$dir_path/$setting/binutils.ecd.$max_state.err.log"
    outfile="$dir_path/$setting/binutils.ecd.$max_state.out.log"
    eval "rm $errfile"
    eval "rm $outfile"
    for binname in $all
    do
        bin_path="$dir_path/$setting/$binname"
        bin_graphs_dir="$bin_path.$ecddir"
        eval "rm -rf $bin_graphs_dir"
        if [[ ! -d "$bin_graphs_dir" ]]; then
            cmd="$py ./build_nx_graphs.py $bin_path --ecddir $ecddir --angrdir $angrdir 2>> $errfile >> $outfile"
            echo $cmd
            eval $cmd
        fi
    done
}

zip_total() {
    max_state=$1
    setting=$2
    ecddir="ecd$ver--maxstate=$max_state.pkl"
    directories=""
    for binname in $all
    do
        bin_graphs_dir="$dir_path/$setting/$binname.$ecddir"
        directories="$directories $(basename $bin_graphs_dir)"
    done
    zip_file="$dir_path/$setting/binutils.$ecddir.zip"
    cur_dir=`pwd`
    cmd="cd $dir_path/$setting && zip $(basename $zip_file) -r $directories > /dev/null && cd $cur_dir"
    echo $cmd
    eval $cmd
}

for max_state in 8
do
    for setting in $settings
    do
        ecd_total $max_state $setting
        zip_total $max_state $setting
    done
done

