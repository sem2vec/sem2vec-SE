from src.vex_tree_utils import *

# def is_ite_assignment(t: Tree):
#     if t.data != 'stmt':
#         return False
#     if t.children[0].data != 'assign_expr':
#         return False
#     if t.children[0].children[1] != 'fun':
#         return False
#     fname = get_fun_fname_str(t.children[0].children[1])
#     return fname == 'ITE'


def get_fun_2_args(t_: Tree):
    assert t_.children[1].data == 'args'
    return t_.children[1].children[0], t_.children[1].children[1]


def _add_naive_simplifier(t: Tree):
    c0, c1 = get_fun_2_args(t)
    if is_Add_fun(c0) and is_num(c1):
        # try to combine 2 Add
        cc0, cc1 = get_fun_2_args(c0)
        if is_num(cc0):
            tmp_v = get_num(cc0) + get_num(c1)
            tmp_args = [int2num_tree(tmp_v, c1.children[0].type), cc1]
            set_fun_args(t, tmp_args)
            return t, True
        elif is_num(cc1):
            tmp_v = get_num(cc1) + get_num(c1)
            tmp_args = [cc0, int2num_tree(tmp_v, c1.children[0].type)]
            set_fun_args(t, tmp_args)
            return t, True
    elif is_Add_fun(c1) and is_num(c0):
        cc0, cc1 = get_fun_2_args(c1)
        if is_num(cc0):
            tmp_v = get_num(cc0) + get_num(c0)
            tmp_args = [int2num_tree(tmp_v, c0.children[0].type), cc1]
            set_fun_args(t, tmp_args)
            return t, True
        elif is_num(cc1):
            tmp_v = get_num(cc1) + get_num(c0)
            tmp_args = [cc0, int2num_tree(tmp_v, c0.children[0].type)]
            set_fun_args(t, tmp_args)
            return t, True
    elif is_Sub_fun(c0) and is_num(c1):
        cc0, cc1 = get_fun_2_args(c0)
        if is_num(cc0):
            # (cc0 - x) + c1  x=cc1
            tmp_v = get_num(cc0) + get_num(c1)
            tmp_args = [int2num_tree(tmp_v, c1.children[0].type), cc1]
            set_fun_args(t, tmp_args)
            return t, True
        elif is_num(cc1):
            # (x - cc1) + c1   x=cc0
            tmp_v = get_num(c1) - get_num(cc1)
            if tmp_v == 0:
                return cc0, True
            if tmp_v < 0:
                func_replace(t, 'Add', 'Sub')
                tmp_v = -tmp_v
            tmp_args = [cc0, int2num_tree(tmp_v, c1.children[0].type)]
            set_fun_args(t, tmp_args)
            return t, True
    elif is_Sub_fun(c1) and is_num(c0):
        cc0, cc1 = get_fun_2_args(c1)
        if is_num(cc0):
            # c0 + (cc0 - x)
            tmp_v = get_num(c0) + get_num(cc0)
            func_replace(t, 'Add', 'Sub')
            tmp_args = [int2num_tree(tmp_v, c0.children[0].type), cc1]
            set_fun_args(t, tmp_args)
            return t, True
        elif is_num(cc1):
            # c0 + (x - cc1)
            tmp_v = get_num(c0) - get_num(cc1)
            if tmp_v == 0:
                return cc0, True
            elif tmp_v < 0:
                func_replace(t, 'Add', 'Sub')
                tmp_v = -tmp_v
            tmp_args = [cc0, int2num_tree(tmp_v, cc1.children[0].type)]
            set_fun_args(t, tmp_args)
            return t, True
    elif is_num(c0) and is_num(c1):
        tmp_v = get_num(c0) + get_num(c1)
        t = int2num_tree(tmp_v, c0.children[0].type)
        return t, True
    return t, False


def _sub_naive_simpifier(t: Tree):
    c0, c1 = get_fun_2_args(t)
    if is_Sub_fun(c0) and is_num(c1):
        cc0, cc1 = get_fun_2_args(c0)
        if is_num(cc0):
            # cc0 - x - c1
            tmp_v = get_num(cc0) - get_num(c1)
            tmp_args = [int2num_tree(tmp_v, cc0.children[0].type), cc1]
            set_fun_args(t, tmp_args)
            return t, True
        elif is_num(cc1):
            # x - cc1 - c1
            tmp_v = get_num(cc1) + get_num(c1)
            tmp_args = [cc0, int2num_tree(tmp_v, cc1.children[0].type)]
            set_fun_args(t, tmp_args)
            return t, True
    elif is_Sub_fun(c1) and is_num(c0):
        cc0, cc1 = get_fun_2_args(c1)
        if is_num(cc0):
            # c0 - (cc0 - x) = (x + c0 - cc0)
            tmp_v = get_num(c0) - get_num(cc0)
            if tmp_v == 0:
                return cc1, True
            if tmp_v > 0:
                func_replace(t, 'Sub', 'Add')
            else:
                tmp_v = -tmp_v
            tmp_args = [cc1, int2num_tree(tmp_v)]
            set_fun_args(t, tmp_args)
            return t, True
        elif is_num(cc1):
            # c0 - (x - cc1) = (c0 + cc1 - x)
            tmp_v = get_num(c0) + get_num(cc1)
            tmp_args = [int2num_tree(tmp_v), cc0]
            set_fun_args(t, tmp_args)
            return t, True
    elif is_Add_fun(c0) and is_num(c1):
        cc0, cc1 = get_fun_2_args(c0)
        if is_num(cc0):
            # cc0 + x - c1
            tmp_v = get_num(cc0) - get_num(c1)
            if tmp_v == 0:
                return cc1, True
            if tmp_v > 0:
                func_replace(t, 'Sub', 'Add')
            else:
                tmp_v = -tmp_v
            tmp_args = [cc1, int2num_tree(tmp_v)]
            set_fun_args(t, tmp_args)
            return t, True
        elif is_num(cc1):
            # x + cc1 - c1
            tmp_v = get_num(cc1) - get_num(c1)
            if tmp_v == 0:
                return cc0, True
            if tmp_v > 0:
                func_replace(t, 'Sub', 'Add')
            else:
                tmp_v = -tmp_v
            tmp_args = [cc0, int2num_tree(tmp_v)]
            set_fun_args(t, tmp_args)
            return t, True
    elif is_Add_fun(c1) and is_num(c0):
        cc0, cc1 = get_fun_2_args(c1)
        if is_num(cc0):
            # c0 - (cc0 + x)
            tmp_v = get_num(c0) - get_num(cc0)
            tmp_args = [int2num_tree(tmp_v), cc1]
            set_fun_args(t, tmp_args)
            return t, True
        elif is_num(cc1):
            # c0 - (x + cc1)
            tmp_v = get_num(c0) - get_num(cc1)
            tmp_args = [int2num_tree(tmp_v), cc0]
            set_fun_args(t, tmp_args)
            return t, True
    elif is_num(c0) and is_num(c1):
        tmp_v = get_num(c0) - get_num(c1)
        t = int2num_tree(tmp_v, c0.children[0].type)
        return t, True
    return t, False


def _and_naive_simplifier(t: Tree):
    c0, c1 = get_fun_2_args(t)
    if is_num(c0) and get_num(c0) == 0:
        t = int2num_tree(0, c0.children[0].type)
        return t, True
    elif is_num(c1) and get_num(c1) == 0:
        t = int2num_tree(0, c1.children[0].type)
        return t, True
    return t, False


def _cmpeq_naive_simplifier(t: Tree):
    c0, c1 = get_fun_2_args(t)
    if is_num(c0) and is_num(c1):
        if get_num(c0) == get_num(c1):
            # static true, return 1 bit 0x1
            t = int2num_tree(1, c0.children[0].type)
        else:
            # static false, return 1 bit 0x0
            t = int2num_tree(0, c0.children[0].type)
        return t, True
    return t, False


def _AtoB_naive_simplifier(t: Tree, A: str, B: str):
    if is_bitvec_size_change(t.children[1].children[0], B, 'Uto', A):
        # trim 64to1 ( 1Uto64 ( ... ) )
        t = t.children[1].children[0].children[1].children[0]
        return t, True
    return t, False


def _redundant_bitvec_op_naive_simplifier(t: Tree):
    for B in [1, 8, 16, 32]:
        for A in [64, 32, 16, 8]:
            if A > B:
                if is_bitvec_size_change(t, str(A), 'to', str(B)):
                    return _AtoB_naive_simplifier(t, str(A), str(B))
    return t, False


def _naive_simplify(t: Tree):
    """
    Naive simplify add and sub with constants
    """
    if is_Add_fun(t):
        return _add_naive_simplifier(t)
    elif is_Sub_fun(t):
        return _sub_naive_simpifier(t)
    elif is_And_fun(t):
        return _and_naive_simplifier(t)
    elif is_CmpEq_fun(t):
        return _cmpeq_naive_simplifier(t)
    return _redundant_bitvec_op_naive_simplifier(t)


def naive_simplify(t: Tree):
    t, ret = _naive_simplify(t)
    while ret:
        t, ret = _naive_simplify(t)

    # recursive approach
    # for c in t.children:
    #     if isinstance(c, Tree):
    #         c = naive_simplify(c)
    stack = [t]
    while len(stack) > 0:
        cur = stack.pop()
        for c_idx in range(len(cur.children)):
            if isinstance(cur.children[c_idx], Tree) and cur.children[c_idx].data != 'fname':
                tmp_c = cur.children[c_idx]
                while True:
                    tmp_c, ret = _naive_simplify(tmp_c)
                    if not ret:
                        break
                # print(tree2str(tmp_c))
                cur.children[c_idx] = tmp_c
                # after simlify children, add them to stack
                if isinstance(cur.children[c_idx], Tree):
                    stack.append(cur.children[c_idx])
    return t


def naive_hard_simplify(t: Tree):
    # change until no modification can be done
    while True:
        done_change_on_children = False
        while True:
            t, ret = _naive_simplify(t)
            if not ret:
                break
            else:
                done_change_on_children = True
        stack = [t]
        while len(stack) > 0:
            cur = stack.pop()
            for c_idx in range(len(cur.children)):
                if isinstance(cur.children[c_idx], Tree) and cur.children[c_idx].data != 'fname':
                    tmp_c = cur.children[c_idx]
                    while True:
                        tmp_c, ret = _naive_simplify(tmp_c)
                        if not ret:
                            break
                        else:
                            done_change_on_children = True
                    # print(tree2str(tmp_c))
                    cur.children[c_idx] = tmp_c
                    # after simlify children, add them to stack
                    if isinstance(cur.children[c_idx], Tree):
                        stack.append(cur.children[c_idx])
        if not done_change_on_children:
            break
    return t
