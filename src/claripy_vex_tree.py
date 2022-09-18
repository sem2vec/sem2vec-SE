from src.vex_tree_utils import *
from src.utils import log
import claripy


class TooComplexClaripyFormulaException(Exception):
    def __init__(self, ast):
        super(TooComplexClaripyFormulaException, self).__init__()
        # do not use it, save it for debug
        self.ast = ast

    def __str__(self):
        return "Too complex formula"

    def __repr__(self):
        return str(self)


def _create_BVV_tree_node(bvv_node):
    v, size = bvv_node.args
    # simply ignore the size info
    return int2num_tree(v, type_='HEX_NUMBER')


def _create_FPV_tree_node(fpv_node):
    v = fpv_node.args[0]
    return float2num_tree(v)


def _create_BVS_tree_node(bvs_node, bvs_map):
    if bvs_node.op == 'Concat':
        bv_name = str(bvs_node)
    else:
        bv_name = bvs_node.args[0]
    if bv_name in bvs_map:
        return bvs_map[bv_name]
    size = bvs_node.size()
    name = ['BV', str(len(bvs_map.keys())), str(size)]
    name = '_'.join(name)
    id_token = Token(type_='NAME', value=name)
    size_token = Token(type_='DEC_NUMBER', value="%d" % size)
    tmp = Tree(data='BV', children=[id_token, size_token])
    bvs_map[bv_name] = tmp
    return tmp


def _create_fun_tree_node(op_node, children: list):
    if isinstance(op_node, claripy.ast.bv.BV):
        fname = op_node.op + str(op_node.size())
    else:
        fname = op_node.op + '1'
    fname_token = Token(value=fname, type_='NAME')
    return create_fun_tree(fname_tokens=[fname_token], args=children)


# (node_type, num_of_args, function_to_build_node)
# -1 means the number of arguments could change
_OPs = {
    '__mul__': ('fun', 'Mul', 2),
    '__add__': ('fun', 'Add', 2),
    '__sub__': ('fun', 'Sub', 2),
    '__eq__': ('fun', 'CmpEQ', 2),
    '__ne__': ('fun', 'CmpNE', 2),
    '__le__': ('fun', 'CmpLE', 2),
    '__lt__': ('fun', 'CmpLT', 2),
    '__ge__': ('fun', 'CmpGE', 2),
    '__gt__': ('fun', 'CmpGT', 2),
    '__rshift__': ('fun', 'Shr', 2),
    '__lshift__': ('fun', 'Shl', 2),
    '__invert__': ('fun', 'Invert', 1),
    '__and__': ('fun', 'And', 2),
    '__or__': ('fun', 'Or', 2),
    'LShR': ('fun', 'LshR', 2),
    'ZeroExt': ('fun', 'ZeroExt', 2),
    'SignExt': ('fun', 'SignExt', 2),
    'Not': ('fun', 'Not', 1),
    'Extract': ('fun', 'Extract', 3),
    'Concat': ('fun', 'Concat', -1),
    'fpLT': ('fun', 'fpLT', 2),
    'fpGT': ('fun', 'fpGT', 2),
}


def select_a_left_side_sub_tree(ast, selected_depth=10):
    if not hasattr(ast, 'depth'):
        return ast
    cur = ast
    while cur.depth > selected_depth:
        for arg in cur.args:
            if isinstance(arg, claripy.ast.bv.BV) or isinstance(arg, claripy.ast.bool.Bool):
                if arg.depth > selected_depth:
                    cur = arg
                    break
                elif arg.depth == selected_depth:
                    return arg
    assert cur.depth <= selected_depth
    return cur


def is_sign_extension(ast):
    if ast.op == 'Concat' and len(ast.args) > 2:
        args = ast.args
        if isinstance(args[0], claripy.ast.bv.BV) and args[0].symbolic and args[0].size() == 1:
            if args[0].op == 'Extract':
                return True
            else:
                tmp = args[0]
                while len(tmp.args) == 1:
                    tmp = tmp.args[0]
                if tmp.op == 'Extract':
                    return True
    return False


def convert_claripy_formula_to_vex_tree(ast, bvs_map, can_sub_tree=False, sub_tree_depth=10):
    """
    claripy formula is an AST
    """
    def is_memory_symbol_concat(_ast):
        if _ast.length % 8 != 0:
            return False
        n = _ast.length // 8
        if n != len(_ast.args) or n not in [2, 4, 8]:
            return False
        last_bvs_id = None
        for idx in range(n):
            if not (_ast.args[idx].symbolic and _ast.args[idx].length == 8 and _ast.args[idx].depth == 1):
                return False
            tmp = _ast.args[idx].args[0].split('_')
            if not tmp[0] == 'mem':
                try:
                    cur_bvs_id = int(tmp[2])
                except Exception:
                    return False
                if last_bvs_id is None:
                    last_bvs_id = cur_bvs_id
                elif last_bvs_id - cur_bvs_id != 1:
                    return False
                else:
                    last_bvs_id = cur_bvs_id
        return True

    if isinstance(ast, claripy.ast.bv.BV) or isinstance(ast, claripy.ast.bool.Bool):
        op = ast.op
        if op == 'BVV':
            return _create_BVV_tree_node(ast)
        elif op == 'FPV':
            return _create_FPV_tree_node(ast)
        elif op == 'BVS':
            return _create_BVS_tree_node(ast, bvs_map)
        elif op == 'Concat':
            if is_memory_symbol_concat(ast):
                return _create_BVS_tree_node(ast, bvs_map)

        # for very complex formula, we merely select a sub-tree of it
        # currently we always select the left hand proper sub-tree
        if ast.depth > 10:
            if not can_sub_tree:
                raise TooComplexClaripyFormulaException(ast)
            else:
                sub_ast = select_a_left_side_sub_tree(ast, selected_depth=sub_tree_depth)
                return convert_claripy_formula_to_vex_tree(sub_ast, bvs_map, can_sub_tree, sub_tree_depth)

        if ast.op in _OPs:
            ast_type = _OPs[ast.op]
            if ast_type[0] == 'fun':
                args = ast.args
                if is_sign_extension(ast):
                    signext = Token(value='SignExt%d' % ast.size(), type_='NAME')
                    child = convert_claripy_formula_to_vex_tree(args[-1], bvs_map, can_sub_tree, sub_tree_depth)
                    extbits_n = ast.size() - args[-1].size()
                    return create_fun_tree([signext], [int2num_tree(extbits_n), child])
                else:
                    children = [convert_claripy_formula_to_vex_tree(arg, bvs_map, can_sub_tree, sub_tree_depth)
                                for arg in args]
                    return _create_fun_tree_node(ast, children)
            else:
                raise NotImplementedError(ast.op)
        else:
            # TODO: now do the same as `fun`
            args = ast.args
            children = [convert_claripy_formula_to_vex_tree(arg, bvs_map, can_sub_tree, sub_tree_depth)
                        for arg in args]
            return _create_fun_tree_node(ast, children)
    elif isinstance(ast, int):
        return int2num_tree(ast)
    elif isinstance(ast, float):
        return float2num_tree(ast)
    else:
        raise NotImplementedError(ast.op)
