from src.vex_parser import Token
from src.vex_parser import Tree as LarkTree
import re


class Tree(LarkTree):

    def __init__(self, data, children, meta=None):
        super(Tree, self).__init__(data, children, meta=None)
        self.size = -1
        self.size = self.get_size()

    def get_size(self):
        if self.size < 0:
            self.size = 1
            for c in self.children:
                if isinstance(c, Tree):
                    self.size += c.get_size()
                elif isinstance(c, Token):
                    continue
                else:
                    assert False, 'Unknown tree node type'
        return self.size

    def replace_child(self, idx, new_child):
        self.size = self.size - self.children[idx].get_size() + new_child.get_size()
        self.children[idx] = new_child


def lark_tree_to_tree(lt):
    if isinstance(lt, Token):
        return lt
    assert isinstance(lt, LarkTree)
    new_children = [lark_tree_to_tree(c) for c in lt.children]
    return Tree(lt.data, new_children)


def is_Add_fun(t_: Tree):
    return t_.data == 'fun' and get_fun_fname_str(t_).startswith('Add')


def is_Sub_fun(t_: Tree):
    return t_.data == 'fun' and get_fun_fname_str(t_).startswith('Sub')


def is_And_fun(t_: Tree):
    return t_.data == 'fun' and get_fun_fname_str(t_).startswith('And')


def is_Mul_fun(t_: Tree):
    return t_.data == 'fun' and get_fun_fname_str(t_).startswith('Mul')


def is_DivMod_fun(t_: Tree):
    return t_.data == 'fun' and get_fun_fname_str(t_).startswith('DivMod')


def is_CmpEq_fun(t_: Tree):
    return t_.data == 'fun' and get_fun_fname_str(t_).startswith('CmpEQ')


def is_Not_fun(t_: Tree):
    return t_.data == 'fun' and get_fun_fname_str(t_).startswith('Not')


def is_If_fun(t_: Tree):
    return t_.data == 'fun' and get_fun_fname_str(t_).startswith('If')


def get_args(t_: Tree):
    return t_.children[1].children


def is_num(t_: Tree):
    return t_.data == 'num'


def is_LDle(t: Tree):
    return t.data == 'fun' and str(t.children[0].children[0]) == 'LDle'


def is_STle(t: Tree):
    return t.data == 'fun' and str(t.children[0].children[0]) == 'STle'


def is_GetI(t: Tree):
    return t.data == 'fun' and str(t.children[0].children[0]) == 'GetI'


def is_GET_reg(t: Tree):
    return t.data == 'fun' and str(t.children[0].children[0]) == 'GET'


def is_bitvec_size_change(t: Tree, _from: str, mid: str, _to: str):
    return t.data == 'fun' and len(t.children[0].children) == 3 and \
           isinstance(t.children[0].children[0], Tree) and isinstance(t.children[0].children[2], Tree) and \
           is_num(t.children[0].children[0]) and t.children[0].children[0].children[0].value == _from and \
           str(t.children[0].children[1]) == mid and \
           is_num(t.children[0].children[2]) and t.children[0].children[2].children[0].value == _to


def is_64to1(t: Tree):
    return is_bitvec_size_change(t, '64', 'to', '1')


def is_1Uto64(t: Tree):
    return is_bitvec_size_change(t, '1', 'Uto', '64')


def GET_reg_name(t: Tree):
    return str(t.children[1].children[0].children[0])


def get_var_str(t: Tree):
    return str(t.children[0])


def get_num(t: Tree):
    if t.children[0].type == 'HEX_NUMBER':
        return int(t.children[0], 16)
    elif t.children[0].type == 'DEC_NUMBER':
        return int(t.children[0])
    elif t.children[0].type == 'FLOAT_NUMBER':
        return float(t.children[0])
    else:
        raise NotImplementedError(t.children[0].type)


def int2num_token(v: int, type_='DEC_NUMBER', pos_in_stream=None, line=None, column=None, end_line=None,
                  end_column=None, end_pos=None):
    if type_ == 'DEC_NUMBER' or type_.lower() == 'dec':
        return Token(type_='DEC_NUMBER', value='%d' % v,
                     pos_in_stream=pos_in_stream, line=line, column=column, end_line=end_line, end_column=end_column,
                     end_pos=end_pos)
    elif type_ == 'HEX_NUMBER' or type_.lower() == 'hex':
        return Token(type_='HEX_NUMBER', value='0x%x' % v if v >= 0 else "-0x%x" % (-v),
                     pos_in_stream=pos_in_stream, line=line, column=column, end_line=end_line, end_column=end_column,
                     end_pos=end_pos)
    else:
        raise NotImplementedError()


def int2num_tree(v: int, type_='DEC_NUMBER', pos_in_stream=None, line=None, column=None, end_line=None, end_column=None,
                 end_pos=None):
    token = int2num_token(v=v, type_=type_, pos_in_stream=pos_in_stream, line=line, column=column, end_line=end_line,
                          end_column=end_column, end_pos=end_pos)
    return Tree(data='num', children=[token])


def float2num_token(v: float, type_='FLOAT', pos_in_stream=None, line=None, column=None, end_line=None,
                    end_column=None, end_pos=None):
    return Token(type_=type_, value=v,
                 pos_in_stream=pos_in_stream, line=line, column=column, end_line=end_line, end_column=end_column,
                 end_pos=end_pos)


def float2num_tree(v: float, type_='FLOAT'):
    token = float2num_token(v, type_)
    return Tree(data='num', children=[token])


def get_num_str(t: Tree, format='dec'):
    n = get_num(t)
    if isinstance(n, float):
        return '%f' % n
    elif format == 'dec':
        return '%d' % n
    elif format == 'hex':
        return '0x%x' % n
    else:
        raise NotImplementedError()


def get_atom(t: Tree):
    if t.data == 'var':
        return get_var_str(t)
    elif t.data == 'num':
        return get_num(t)


def get_atom_str(t: Tree):
    if t.data == 'var':
        return get_var_str(t)
    elif t.data == 'num':
        return get_num_str(t)


def get_args_str(t: Tree, split=',', _tree2str=None, special_handlers=None):
    assert t.data == 'args'
    if _tree2str is None:
        _tree2str = tree2str
    ret = _tree2str(t.children[0], special_handlers)
    for arg in t.children[1:]:
        ret += split + _tree2str(arg, special_handlers)
    return ' ( ' + ret + ' ) '


def get_fname_str(t: Tree, _tree2str=None, special_handlers=None):
    assert t.data == 'fname'
    if _tree2str is None:
        _tree2str = tree2str
    ret = ''
    for _i in t.children:
        if isinstance(_i, Token):
            ret += str(_i)
        elif isinstance(_i, str):
            # some manually inserted string
            ret += _i
        elif _i.data == 'num':
            ret += get_num_str(_i, 'dec')
        else:
            ret += tree2str(_i, special_handlers)
    return ret


def get_fun_fname_str(t: Tree, _tree2str=None):
    assert t.data == 'fun'
    # the first child is always fname
    return get_fname_str(t.children[0], _tree2str)


def get_fun_fname_tokens(t: Tree):
    assert t.data == 'fun'
    return t.children[0].children


def get_bitvec_str(t: Tree, trim_useless=True):
    assert t.data == 'BV'
    if not trim_useless:
        return str(t.children[0])
    else:
        # only id and size info are useful
        # tmp[0] is always 'BV'
        bv_str = str(t.children[0])
        tmp = bv_str.split('_')
        return '_'.join(tmp[:3])


def tree2str(t: Tree, special_handlers=None):
    """
    This is a recursive function
    special_handler is a list of tuple, (filter_function, handle_function)
    """
    if special_handlers:
        for handler in special_handlers:
            if handler[0](t):
                return handler[1](t, special_handlers)

    if t.data == 'stmt':
        return tree2str(t.children[0], special_handlers)
    elif t.data == 'assign_expr':
        if len(t.children) == 2:
            return '( %s ) = ( %s )' % (tree2str(t.children[0], special_handlers),
                                        tree2str(t.children[1], special_handlers))
        elif len(t.children) == 3:
            return '( %s ) = ( %s ) ; %s' % (tree2str(t.children[0], special_handlers),
                                             tree2str(t.children[1], special_handlers),
                                             tree2str(t.children[2], special_handlers))
        else:
            raise Exception('unknown assign_expr format')
    elif t.data == 'if':
        if len(t.children) == 2:
            return 'if ( %s ) { %s }' % (tree2str(t.children[0], special_handlers),
                                         tree2str(t.children[1], special_handlers))
        elif len(t.children) == 3:
            return 'if ( %s ) { %s } else { %s }' % (tree2str(t.children[0], special_handlers),
                                                     tree2str(t.children[1], special_handlers),
                                                     tree2str(t.children[2], special_handlers))
        else:
            raise Exception('unknown if format')
    elif t.data == 'fun':
        ret = get_fname_str(t.children[0], special_handlers=special_handlers)
        if t.children[1].data == 'args':
            ret += get_args_str(t.children[1], split=' , ', special_handlers=special_handlers)
            if len(t.children) == 3:
                ret += ' : ' + tree2str(t.children[2], special_handlers)
        else:
            ret += ' ( ' + get_atom_str(t.children[1]) + ' : ' + get_atom_str(t.children[2]) + ' ) [ ' + \
                   tree2str(t.children[3], special_handlers) + ' , ' + tree2str(t.children[4], special_handlers) + ' ]'
        return ret
    elif t.data == 'fname':
        return get_fname_str(t, special_handlers=special_handlers)
    elif t.data == 'args':
        return get_args_str(t, special_handlers=special_handlers)
    elif t.data == 'var':
        return get_var_str(t)
    elif t.data == 'num':
        return get_num_str(t, 'hex')
    elif t.data == 'BV':
        return get_bitvec_str(t)
    else:
        raise NotImplementedError("Unknown tree node type")


def tree2str_post_sequence(t: Tree):
    """
    This is a recursive function
    """
    if t.data == 'stmt':
        return tree2str_post_sequence(t.children[0])
    elif t.data == 'assign_expr':
        if len(t.children) == 2:
            return '%s %s assign' % (tree2str_post_sequence(t.children[0]), tree2str_post_sequence(t.children[1]))
        elif len(t.children) == 3:
            return '%s %s assign; %s' % (tree2str_post_sequence(t.children[0]), tree2str_post_sequence(t.children[1]),
                                         tree2str_post_sequence(t.children[2]))
        else:
            raise Exception('unknown assign_expr format')
    elif t.data == 'if':
        if len(t.children) == 2:
            return '%s %s if' % (tree2str_post_sequence(t.children[0]), tree2str_post_sequence(t.children[1]))
        elif len(t.children) == 3:
            return '%s %s %s if-else' % (tree2str_post_sequence(t.children[0]),
                                         tree2str_post_sequence(t.children[1]),
                                         tree2str_post_sequence(t.children[2]))
    elif t.data == 'fun':
        ret = ''
        if t.children[1].data == 'args':
            ret += get_args_str(t.children[1], split=' ', _tree2str=tree2str_post_sequence)[1:-1]  # remove brackets
            if len(t.children) == 3:
                ret += ' : ' + tree2str_post_sequence(t.children[2])
        else:
            ret += get_atom_str(t.children[1]) + ' ' + get_atom_str(t.children[2]) + ' ' + \
                   tree2str_post_sequence(t.children[3]) + ' ' + tree2str_post_sequence(t.children[4])
        ret += ' ' + get_fname_str(t.children[0], _tree2str=tree2str_post_sequence)
        return ret
    elif t.data == 'var':
        return get_var_str(t)
    elif t.data == 'num':
        return get_num_str(t, 'hex')
    elif t.data == 'BV':
        return get_bitvec_str(t)
    else:
        raise NotImplementedError("Unknown tree node type")


def set_fun_fname(t_: Tree, n: str):
    assert t_.children[0].data == 'fname'
    t_.children[0].children[0].value = n


def func_replace(t_: Tree, old_: str, new_: str):
    tmp_fname = get_fun_fname_str(t_)
    tmp_fname = tmp_fname.replace(old_, new_)
    set_fun_fname(t_, tmp_fname)


def set_fun_args(t_: Tree, args: list):
    assert t_.children[1].data == 'args'
    t_.children[1].children = args


def get_fun_args(t_: Tree) -> list:
    assert t_.children[1].data == 'args'
    return t_.children[1].children


def get_not_tree(t):
    not_fname = Tree(data='fname', children=[Token(type_='NAME', value='Not')])
    args = Tree(data='args', children=[t])
    ret = Tree(data='fun', children=[not_fname, args])
    return ret


def LD_to_deref(t: Tree):
    return 'deref', get_var_str(t.children[1].children[0])


def ST_to_deref(t: Tree):
    return 'deref', tree2str(t.children[1].children[0])


def GetI_PutI_key(t: Tree):
    ret = 'derefarr'
    for _t in t.children[1:3]:
        ret += '__' + str(_t.children[0])
    return ret, get_atom(t.children[3]), get_atom(t.children[4])


def var_to_key(t: Tree):
    var_str = get_var_str(t)
    if var_str.startswith('t'):
        return 'tmp', var_str
    else:
        return 'reg', var_str


def get_fun_fname_tokens(t_: Tree):
    assert t_.data == 'fun'
    return t_.children[0].children


def create_fun_tree(fname_tokens: list, args: list) -> Tree:
    fname_tree = Tree(data='fname', children=fname_tokens)
    args_tree = Tree(data='args', children=args)
    return Tree(data='fun', children=[fname_tree, args_tree])


_g_BV_index = 1


def create_BV_node(size, name=None) -> Tree:
    global _g_BV_index
    bv_name = ['BV', str(_g_BV_index), str(size)]
    if name is not None:
        bv_name.append(name)
    bv_name = '_'.join(bv_name)
    id_token = Token(type_='NAME', value=bv_name)
    size_token = Token(type_='DEC_NUMBER', value="%d" % size)
    _g_BV_index += 1
    return Tree(data='BV', children=[id_token, size_token])


def set_g_BV_index(idx):
    global _g_BV_index
    _g_BV_index = idx


def get_GET_size(t: Tree) -> int:
    size_info = str(t.children[0].children[-1])
    tmp = re.search('[0-9]+', size_info).span()
    size = int(size_info[tmp[0]:tmp[1]])
    return size


def create_BV_with_GET(t: Tree) -> Tree:
    """
    t is a Get:Ixx(reg) function expression
    """
    assert is_GET_reg(t)
    reg = GET_reg_name(t)
    size = get_GET_size(t)
    return create_BV_node(size, reg)


def get_LD_size(t: Tree) -> int:
    size_info = str(t.children[0].children[-1])
    tmp = re.search('[0-9]+', size_info).span()
    size = int(size_info[tmp[0]:tmp[1]])
    return size


def create_BV_with_LD(t: Tree) -> Tree:
    assert is_LDle(t)
    size = get_LD_size(t)
    return create_BV_node(size)
