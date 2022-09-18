from src.utils import *
import sys
import pickle


def get_block_irsb_raw_str(block):
    res = "IRSB { 0x%x\n" % block.addr
    res += block.vex._pp_str()[7:] + '\n'
    return res


def get_irsbs_raw_str(cfg):
    res = ''
    for n in cfg.model.nodes():
        if n.block is not None:
            res += get_block_irsb_raw_str(n.block)
    return res


def get_irsbs_raw_str_linearly(p: angr.Project):
    text_range = get_section_range(p, '.text')
    block_addr = text_range[0]
    res = ''
    while block_addr in text_range:
        tmp_b = p.factory.block(addr=block_addr)
        res += get_block_irsb_raw_str(tmp_b)
        block_addr += tmp_b.size
    return res


def get_insns_raw_str(cfg):
    res = []
    for n in cfg.model.nodes():
        if n.block is not None:
            res.append(str(n.block.capstone))
    return '\n'.join(res)


def get_insns_raw_str_linearly(p: angr.Project):
    text_range = get_section_range(p, '.text')
    block_addr = text_range[0]
    res = []
    while block_addr in text_range:
        tmp_b = p.factory.block(addr=block_addr)
        res.append(str(tmp_b.capstone))
        block_addr += tmp_b.size
    return '\n'.join(res)


def get_insns_map(insns_raw_str: str):
    lines = insns_raw_str.split('\n')
    res = dict()
    for l in lines:
        tmp = l.split(':')
        tmp_addr = int(tmp[0].strip(), 16)
        tmp_insn = tmp[1].strip()
        res[tmp_addr] = tmp_insn
    return res


def main(bin_path):
    irsbs_path = bin_path + '.IRSBs'
    insns_path = bin_path + '.insns.pkl'
    p = load_proj(bin_path)
    cfg = p.analyses.CFGFast()
    irsbs_res = get_irsbs_raw_str(cfg)
    insns_res = get_insns_raw_str(cfg)
    # irsbs_res = get_irsbs_raw_str_linearly(p)
    # insns_res = get_insns_raw_str_linearly(p)
    insns_map = get_insns_map(insns_res)
    with open(irsbs_path, 'w') as f:
        f.write(irsbs_res)
    with open(insns_path, 'wb') as f:
        pickle.dump(insns_map, f)


if __name__ == '__main__':
    main(sys.argv[1])
