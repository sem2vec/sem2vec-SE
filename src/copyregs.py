import angr


def copy_regs_amd64(_from, _to):
    pass
    # _to.regs.eax = _from.regs.eax
    _to.regs.rax = _from.regs.rax
    # _to.regs.rbx = _from.regs.rbx
    # _to.regs.rcx = _from.regs.rcx
    # _to.regs.rdx = _from.regs.rdx
    #
    # _to.regs.r8 = _from.regs.r8
    # _to.regs.r9 = _from.regs.r9
    # _to.regs.r10 = _from.regs.r10
    # _to.regs.r11 = _from.regs.r11
    # _to.regs.r12 = _from.regs.r12
    # _to.regs.r13 = _from.regs.r13
    # _to.regs.r14 = _from.regs.r14
    # _to.regs.r15 = _from.regs.r15
    #
    # _to.regs.rsi = _from.regs.rsi
    # _to.regs.rdi = _from.regs.rdi
    #
    # _to.regs.rbp = _from.regs.rbp
    # _to.regs_rsp = _from.regs.rsp


def copy_regs_x86(_from, _to):
    _to.regs.eax = _from.regs.eax


def copy_regs_aarch64(_from, _to):
    raise NotImplementedError()


def get_copy_regs_func_ptr(p: angr.Project):
    if p.arch.name == 'AMD64':
        return copy_regs_amd64
    elif p.arch.name == 'X86':
        return copy_regs_x86
    elif p.arch.name == 'AARCH64':
        return copy_regs_aarch64
    else:
        raise NotImplementedError()
