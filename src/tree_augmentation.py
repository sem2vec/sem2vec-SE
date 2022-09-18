from src.vex_tree_utils import *
from copy import deepcopy


def _swap_args_of_add_mul(t: Tree):
    """
    The arguments of Add and Mul could be swapped
    """
    if is_Add_fun(t) or is_Mul_fun(t):
        new_args = list(reversed(get_args(t)))
        return create_fun_tree(get_fun_fname_tokens(t), new_args)
    else:
        return None


def augment_with_add_mul(t: Tree):
    # for every new tree, switch arguments of 1 Add/Mul merely
    new_trees = []
    # identify all Add and Mul nodes, then create trees for each of them
    new_t0 = _swap_args_of_add_mul(t)
    if new_t0 is not None:
        new_trees.append(new_t0)
    stack = [t]
    while len(stack):
        cur = stack.pop()
        for idx in range(len(cur.children)):
            if not isinstance(cur.children[idx], Tree):
                continue
            stack.append(cur.children[idx])
            swapped_child = _swap_args_of_add_mul(cur.children[idx])
            if swapped_child is not None:
                # replace the child node, deepcopy the whole tree and add to list
                tmp_child = cur.children[idx]
                cur.children[idx] = swapped_child
                new_trees.append(deepcopy(t))
                # then recover the old child for next search
                cur.children[idx] = tmp_child
    return new_trees
