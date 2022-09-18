"""
Compare 2 tracelet
A tracelet is a tuple of (constraints: list, expressions: dict)
For a single tracelet, the input are
    1. variables of reading from registers
    2. load from memory addresses

While comparing 2 tracelets, we compare constraints and expressions respectively
"""
from lark import Tree

FUNC_ARGS = [
    ('reg', 'rdi'),
    ('reg', 'rsi'),
    ('reg', 'rdx'),
    ('reg', 'rcx'),
    ('reg', 'r8'),
    ('reg', 'r9'),
    ('reg', 'xmm0'),
    ('reg', 'xmm1'),
    ('reg', 'xmm2'),
    ('reg', 'xmm3'),
    ('reg', 'xmm4'),
    ('reg', 'xmm5'),
    ('reg', 'xmm6'),
    ('reg', 'xmm7'),
    # ('reg', 'r10'),
]


def compare_expression_with_normalization(a: Tree, b: Tree):
    pass


def compare_constraints(ca: list, cb: list):
    """
    for constraints a and b
    an essential thing is that the element of constraints may not be built in order
    empty constraints list means a always true condition
    it is always 0 no matter compared to anyone
    """
    if len(ca) == 0 or len(cb) == 0:
        return 0.0
    eq_pairs = dict()  # (b_idx: a_idx)
    for i in range(len(ca)):
        a = ca[i]
        for j in range(len(cb)):
            if j in eq_pairs.keys():
                continue
            b = cb[j]
            if a == b:
                eq_pairs[j] = i
                break
    # simply compute a score now
    return len(eq_pairs.keys()) / max(len(ca), len(cb))


def compare_func_args_expressions(a_exprs: dict, b_exprs: dict, a_arg_num=None, b_arg_num=None):
    """
    The value's expression which is not used a function parameter has few meaning
    For x86_64 arch, we here simply use function arguments as valid expressions
    The function may slightly changed, especially lib calls may change by compiler
    Therefore, the order of these registers is not constrained
    """
    a_args = dict()
    b_args = dict()
    arg_idx = 0
    for reg_key in FUNC_ARGS:
        if a_arg_num is None or arg_idx < a_arg_num:
            if reg_key in a_exprs:
                a_args[reg_key[1]] = a_exprs[reg_key]
        if b_arg_num is None or arg_idx < b_arg_num:
            if reg_key in b_exprs:
                b_args[reg_key[1]] = b_exprs[reg_key]
        arg_idx += 1

    matched = dict()  # (b_reg: a_reg)
    for a_reg, a_expr in a_args.items():
        # we still compare expressions in the same registers first
        if a_reg in b_args.keys():
            if a_expr == b_args[a_reg]:
                matched[a_reg] = a_reg
                continue
        for b_reg, b_expr in b_args.items():
            if a_reg == b_reg:
                # it has been compared already
                continue
            if b_reg in matched.keys():
                continue
            if a_expr == b_expr:
                matched[b_reg] = a_reg
                break
    # simply return the proportion of matched arguments
    return len(matched.keys()) / max(len(a_args.keys()), len(b_args.keys()))


def compare_tracelet(ta, tb):
    """
    compare tracelet a and b
    """
    ca, a_exprs = ta
    cb, b_exprs = tb
    c_sim = compare_constraints(ca, cb)
    e_sim = compare_func_args_expressions(a_exprs, b_exprs)
    return c_sim, e_sim


def compare_traces(tsa, tsb):
    sims = dict()
    sim = 0.0
    for ta_idx in range(len(tsa)):
        ta = tsa[ta_idx]
        sims[ta_idx] = []
        for tb_idx in range(len(tsb)):
            tb = tsb[tb_idx]
            tmp_c_sim, tmp_e_sim = compare_tracelet(ta, tb)
            sims[ta_idx].append(tmp_c_sim + tmp_e_sim)
        sim += max(sims[ta_idx])
    return sim / len(tsa)
