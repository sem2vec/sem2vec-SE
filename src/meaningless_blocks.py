from src.state_plugins import create_blank_state


_meaningless_blocks_cache = dict()


def possible_flatten_meaningless(cmp_capstone_insn):
    if len(cmp_capstone_insn.operands) != 2:
        return False
    if cmp_capstone_insn.operands[0].size != 4 or cmp_capstone_insn.operands[1].size != 4:
        return False
    if cmp_capstone_insn.operands[1].type == 2:
        if cmp_capstone_insn.operands[1].reg > 255:
            v_str = '%x' % cmp_capstone_insn.operands[1].reg
            if 6 <= len(v_str) <= 8 and v_str not in ['ffffffff', '7fffffff']:
                return True
    return False


def _is_immediate(oprand_str):
    # quick trick
    return oprand_str.strip().startswith('0x')


def _is_conditional_jump(instr):
    return instr.mnemonic.startswith('j') and 'jmp' not in instr.mnemonic


def _is_any_jump(instr):
    return instr.mnemonic.startswith('j')


def _is_direct_jump(instr):
    if instr.mnemonic.startswith('j'):
        # is a hex number
        return _is_immediate(instr.op_str)
    return False


def is_meaningless_pattern1(b):
    if b.instructions >= 1:
        insns = b.capstone.insns
        if insns[-1].insn.mnemonic == 'jmp':
            return True
    return False


def is_meaningless_pattern2(b):
    if b.instructions == 2:
        insns = b.capstone.insns
        if insns[0].insn.mnemonic == 'cmp' and _is_any_jump(insns[1].insn):
            return possible_flatten_meaningless(insns[0].insn)
    return False


def is_meaningless_pattern3_1(b):
    if b.instructions == 3:
        insns = b.capstone.insns
        if insns[0].insn.mnemonic == 'cmp' and _is_any_jump(insns[2].insn) \
                and insns[1].insn.mnemonic == 'mov':
            return possible_flatten_meaningless(insns[0].insn)
    return False


def is_meaningless_pattern3_2(b):
    if b.instructions == 3:
        insns = b.capstone.insns
        if insns[1].insn.mnemonic == 'cmp' and _is_any_jump(insns[2].insn) \
                and (insns[0].insn.mnemonic in ['mov', 'and'] or insns[0].insn.mnemonic.startswith('cmov')):
            return possible_flatten_meaningless(insns[1].insn)
    return False


def is_meaningless_pattern4(b):
    if b.instructions == 4:
        insns = b.capstone.insns
        if insns[0].insn.mnemonic == 'mov' and insns[1].insn.mnemonic.startswith('sub') \
                and insns[2].insn.mnemonic == 'mov' and insns[3].insn.mnemonic == 'je':
            return possible_flatten_meaningless(insns[1].insn)
    return False


def is_meaningless_pattern5(b):
    if b.instructions >= 5:
        insns = b.capstone.insns
        if insns[0].insn.mnemonic == 'cmovge' and insns[1].insn.mnemonic == 'xor' \
                and insns[2].insn.mnemonic == 'cmovne' and _is_any_jump(insns[-1].insn) \
                and insns[-2].insn.mnemonic == 'cmp':
            return possible_flatten_meaningless(insns[-2].insn)
    return False


def is_meaningless_pattern_merely_mov_cmov_cmp(b):
    # seems useless
    if b.instructions >= 6:
        insns = b.capstone.insns
        if _is_any_jump(insns[-1].insn) and insns[-2].insn.mnemonic == 'cmp' \
                and possible_flatten_meaningless(insns[-2].insn):
            all_mov_cmov_cmp = True
            for insn in insns[:-2]:
                if not (insn.insn.mnemonic in ('mov', 'cmp') or insn.insn.mnemonic.startswith('cmov')):
                    all_mov_cmov_cmp = False
                    break
            return all_mov_cmov_cmp
    return False


def is_meaningless_pattern_deterministic_conditional_jump(b):
    if b.instructions >= 3:
        insns = b.capstone.insns
        if _is_direct_jump(insns[-1].insn) and insns[-2].insn.mnemonic == 'cmp':
            # the mov may have initialized the value in register, so this is not a real branch, continue it
            idx = b.instructions - 3
            reg_name = None
            while idx >= 0:
                if insns[idx].insn.mnemonic == 'mov':
                    being_assigned = insns[idx].insn.op_str.split(', ')
                    being_compared = insns[-2].insn.op_str.split(', ')
                    if len(being_assigned) == 2 and _is_immediate(being_assigned[1]) \
                            and len(being_compared) == 2 and _is_immediate(being_compared[1]) \
                            and being_assigned[0] == being_compared[0]:
                        reg_name = being_compared[0]
                        break
                idx -= 1
            if idx >= 0:
                # from index to conditional jump, no reference to the register
                for insn in insns[idx + 1:b.instructions - 2]:
                    if reg_name in insn.insn.op_str:
                        return False
                return True
    return False


_pattern_func_list = [
    is_meaningless_pattern1,
    is_meaningless_pattern2,
    is_meaningless_pattern3_1,
    is_meaningless_pattern3_2,
    is_meaningless_pattern4,
    is_meaningless_pattern5,
    # is_meaningless_pattern_merely_mov_cmov_cmp,
    is_meaningless_pattern_deterministic_conditional_jump
]


def is_meaningless_block(b):
    if b.addr in _meaningless_blocks_cache:
        return _meaningless_blocks_cache[b.addr]
    for pf in _pattern_func_list:
        if pf(b):
            _meaningless_blocks_cache[b.addr] = True
            return True
    _meaningless_blocks_cache[b.addr] = False
    return False
