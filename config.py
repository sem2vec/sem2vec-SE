import argparse

config_parser = argparse.ArgumentParser(description='Process the inputs')
config_parser.add_argument('bin_path', type=str, nargs='*', help='The path to the binary to be processed')
config_parser.add_argument('--others', type=str, nargs='*', help='A project may have lots of common functions, skip functions which have been collected in other binaries')
config_parser.add_argument('--max_state', type=int, default=8, help='the max number of states starting from a block')
config_parser.add_argument('--tracelet_limit', type=int, default=1000, help='The upper limit number of tracelets to be collected from a function')
config_parser.add_argument('--process', type=int, default=8, help='the number of process')
config_parser.add_argument('--timeout', type=int, default=1200, help='the seconds to timeout a process for a function (not effective when process is 1)')
config_parser.add_argument('--mem_limit', type=int, default=20 * (2**30), help='the memory limit for per function process(default is 20GB)')

config_parser.add_argument('--overlap_tracelet', action='store_true')
config_parser.add_argument('--copy_regs', type=bool, default=True)

config_parser.add_argument('--target-func', type=str, default='', help='the name or the address of the target function. It only works when process=1.'
                                                                       'Addresses must start with 0 if decimal, 0x if hex.')

config_parser.add_argument('--bin_paths_txt', type=str, default='', help='The path to a text file with all binaries to be processed')


config_parser.add_argument('--is-flatten', action='store_true')
config_parser.add_argument('--block-callee', action='store_true', help='For the esh-dataset, the callees are all only ret functions')
config_parser.add_argument('--callee-limiter', action='store_true', help='limit the number of blocks to be executed in callees')
config_parser.add_argument('--callee-limit-len', type=int, default=100)
config_parser.add_argument('--without-inloop', action='store_true', help='does not collect tracelets trapped in loops')

config_parser.add_argument('--skip-exists', action='store_true', help='Skip functions with tracelets pkl files')
config_parser.add_argument('--skip-same-fnames', action='store_true', help='Skip functions with same names, except `main`, in different binaries.')

VERSION = '9.5.3'
config_parser.add_argument('--version', action='version', version=VERSION)
config_parser.add_argument('--angrdir', type=str, default=f"angr{VERSION}.pkl")
config_parser.add_argument('--ecddir', type=str, default=f"ecd{VERSION}.pkl")

args = config_parser.parse_args()
