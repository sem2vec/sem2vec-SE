import claripy
from claripy.ast.bv import BV as CBV, Bool as CBool


def is_const_bitvec(e):
    return isinstance(e, CBV) and (not e.symbolic)


def get_const_value(e):
    return e.args[0]


def simplify_pattern1(e):
    if isinstance(e, CBool):
        if len(e.args) == 2 and e.op in ['SLE', 'SGE', 'SLT', 'SGT', '__eq__', '__ne__']:
            if is_const_bitvec(e.args[1]) and e.args[1].length == 32:
                left_v = e.args[1].args[0]
                if len(e.args[0].args) == 2 and e.args[0].op in ['__add__']:
                    if is_const_bitvec(e.args[0].args[1]) and e.args[0].args[1].length == 32:
                        right_v = e.args[0].args[1].args[0]
                        v = left_v - right_v
                        if v < 0:
                            v += 0xffffffff + 1
                        return claripy.ast.Bool(op=e.op, args=(e.args[0].args[0], claripy.BVV(v, 32)))
    return None


def simplify_pattern2(e):
    # [<Bool (SignExt(32, reg_rax_7_64{UNINITIALIZED}[31:0]) >> 0x1f[31:0] & 0xa329cc9d) <=s 0xffffffff>]
    # this formula only use the sign value of reg_rax_7_64{UNINITIALIZED}[31:31] != 0
    if isinstance(e, CBool) and e.op in ['SLE', 'SGE', 'SLT', 'SGT', '__eq__', '__ne__']:
        le = e.args[0]
        re = e.args[1]
        if isinstance(le, CBV) and le.op == '__and__' and le.length == 32 and is_const_bitvec(re):
            if is_const_bitvec(le.args[1]):
                tmp = le.args[0]
                if isinstance(tmp, CBV) and tmp.op == 'Extract':
                    tmp = tmp.args[2]
                    if isinstance(tmp, CBV) and tmp.length == 64 and tmp.op == '__rshift__':
                        if is_const_bitvec(tmp.args[1]) and get_const_value(tmp.args[1]) == 31:
                            if isinstance(tmp.args[0], CBV) and tmp.args[0].op == 'SignExt':
                                sv = tmp.args[0].args[1] # may not be symbolic?
                                if isinstance(sv, CBV):
                                    top_bit_index = sv.length - 1
                                    new_le = claripy.SignExt(31, sv[top_bit_index])
                                    return claripy.ast.Bool(op=e.op, args=(new_le, re))
    return None


def simplify_pattern3(e):
    if isinstance(e, CBool) and e.op in ['SLE', 'SGE', 'SLT', 'SGT', '__eq__', '__ne__']:
        le = e.args[0]
        re = e.args[1]
        if isinstance(le, CBV) and le.op == 'SignExt' and isinstance(le.args[1], CBV) and le.args[1].length == 1:
            # it is a 1-bit sign extension
            if is_const_bitvec(re):
                if (re.length == 32 and get_const_value(re) == 0xffffffff) \
                        or (re.length == 64 and get_const_value(re) == 0xffffffffffffffff):
                    # right hand side is -1
                    if e.op in ['SLE', '__eq__']:
                        return le.args[1] != 0
                    elif e.op in ['SGT', '__ne__']:
                        return le.args[1] == 0
                elif get_const_value(re) == 0:
                    if e.op in ['SGE', '__eq__']:
                        return le.args[1] == 0
                    elif e.op in ['SLT', '__ne__']:
                        return le.args[1] != 0
    return None


def simplify_pattern4(e):
    """
    This simplification tries to transform the constraint pattern
    something like 0 <= eax / eax < 0, can be transformed to eax[31:31] == 0 / not(eax[31:31] == 0)
    """
    if isinstance(e, CBool) and e.op in ['SLE', 'SLT', 'SGE', 'SGT']:
        le = e.args[0]
        re = e.args[1]
        if e.op == 'SLE':
            # 0 <= eax ==> 0 == eax[31:31]
            if is_const_bitvec(le) and get_const_value(le) == 0 and re.symbolic:
                return re[re.length-1:re.length-1] == 0
        elif e.op == 'SGT':
            # 0 > eax ==> 0 != eax[31:31]
            if is_const_bitvec(le) and get_const_value(le) == 0 and re.symbolic:
                return re[re.length-1:re.length-1] != 0
        elif e.op == 'SGE':
            # eax >= 0
            if is_const_bitvec(re) and get_const_value(re) == 0 and le.symbolic:
                return le[le.length-1:le.length-1] == 0
        elif e.op == 'SLT':
            # eax < 0
            if is_const_bitvec(re) and get_const_value(re) == 0 and le.symbolic:
                return le[le.length-1:le.length-1] != 0
    elif isinstance(e, CBool) and e.op == 'Not':
        tmp = simplify_pattern4(e.args[0])
        if tmp is not None:
            return claripy.Not(tmp)
    return None


def simplify_flatten_constraint(e):
    changed = False
    simplifiers = [simplify_pattern1, simplify_pattern2, simplify_pattern3, simplify_pattern4]
    cur = e
    for simplifier in simplifiers:
        ret = simplifier(cur)
        if ret is not None:
            changed = True
            cur = ret
    if changed:
        return simplify_flatten_constraint(cur)
    else:
        return cur



