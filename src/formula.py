import enum
import copy
import claripy
from claripy.operations import infix, prefix


class BASIC_OP_TYPE(enum.Enum):
    MEM = 0,
    REG = 1,
    CONST = 2,
    TEMP = 3,


_g_type_dict = {
    'mem': BASIC_OP_TYPE.MEM,
    'reg': BASIC_OP_TYPE.REG,
    'BVV': BASIC_OP_TYPE.CONST,
    'tmp': BASIC_OP_TYPE.TEMP
}


def str2type(s: str):
    if s in _g_type_dict:
        return _g_type_dict[s]
    return s


class FormulaNode:

    def __init__(self, op, name, size, depth, args=None):
        self.op = op
        self.name = name
        self.size = size
        self.depth = depth
        self.args = args

    def set_args(self, args):
        self.args = args

    def to_basic_key(self):
        """
        This key can easily crash, merely used for register, memory, const
        """
        assert self.args is None
        return self.op, self.name, self.size, self.depth

    def copy(self):
        return FormulaNode(self.op,
                           self.name,
                           self.size,
                           self.depth,
                           copy.deepcopy(self.args))

    def to_deref(self, ptr_info):
        assert self.op == BASIC_OP_TYPE.MEM
        self.name = 'deref'
        self.depth = ptr_info.depth + 1
        self.args = (ptr_info,)

    def __str__(self):
        if self.op == BASIC_OP_TYPE.REG:
            return self.name
        elif self.op == BASIC_OP_TYPE.MEM:
            if self.name == 'deref':
                return '(*%s)[0,%d]' % (str(self.args[0]), self.size)
            else:
                return '(*%x)[0,%d]' % (self.name, self.size)
        elif self.op == BASIC_OP_TYPE.CONST:
            return '0x%x#%d' % (self.name, self.size)
        elif self.op in infix:
            tmp = map(lambda a: '(%s)' % str(a), self.args)
            tmp = (' %s ' % infix[self.op]).join(tmp)
            return tmp
        elif self.op in prefix:
            return '%s(%s)' % (str(self.args[0]), prefix[self.op])
        elif self.op == 'Extract':
            return '%s[%s:%s]' % (str(self.args[2]), str(self.args[0]), str(self.args[1]))
        elif self.op == 'Reverse':
            return 'Reverse%s' % str(self.args)
        elif self.op == 'ZeroExt':
            return "(0#%d .. %s)" % (self.args[0], self.args[1])
        else:
            tmp = self.op + '('
            for arg in self.args:
                tmp += str(arg) + ', '
            tmp += ')'
            return tmp
            # raise Exception('Unknow op! %s, %s' % (str(self.op), str(self.args)))

    def __repr__(self):
        return str(self)

    @staticmethod
    def get_depth_1_node(expr):
        assert expr.depth == 1, "the depth is not 1!"
        # tmp = str(expr._encoded_name, encoding='utf-8').split('_')
        if expr.symbolic:
            tmp = expr.args[0].split('_')
            op = tmp[0]
            if op == 'mem':
                # for mem, the name is address value
                name = int(tmp[1], 16)
            else:
                name = tmp[1]
            size = expr.length
        else:
            op = expr.op
            name = expr.args[0]
            size = expr.length
        op = str2type(op)
        return FormulaNode(op, name, size, 1)

    @staticmethod
    def get_formula_tree(expr):
        """
        We give up when the expression is too complex (extra-ordinary depth)
        """
        if not hasattr(expr, 'depth'):
            return expr
        if expr.depth == 1:
            return FormulaNode.get_depth_1_node(expr)
        if expr.depth > 100:
            return None
        depth = expr.depth
        op = expr.op
        # TODO: change the operation to readable format
        name = op
        args = []
        for arg in expr.args:
            args.append(FormulaNode.get_formula_tree(arg))
        if op == 'Extract':
            size = args[0] - args[1] + 1
        elif op in ['ZeroExt', 'SignExt']:
            size = args[0] + args[1].size
        else:
            size = args[0].size
        return FormulaNode(op, name, size, depth, tuple(args))

    @staticmethod
    def _rebuild(formula, ptr_map, done_map):
        if not isinstance(formula, FormulaNode):
            return formula
        if formula.depth == 1:
            if formula.to_basic_key() in done_map.keys():
                return done_map[formula.to_basic_key()].copy()
            elif formula.op == BASIC_OP_TYPE.REG:
                return formula
            if formula.op == BASIC_OP_TYPE.MEM:
                if formula.name in ptr_map.keys():
                    # this could be a multi-deref process
                    tmp = ptr_map[formula.name][0]
                    new_tmp = FormulaNode._rebuild(tmp, ptr_map, done_map)
                    new_formula = formula.copy()
                    new_formula.to_deref(new_tmp)
                    done_map[formula.to_basic_key()] = new_formula
                    return new_formula
                else:
                    # TODO: we may fail to handle it, or it simply loads data from a exact memory block
                    return formula
            else:
                return formula
        else:
            args = []
            depth = formula.depth
            for arg in formula.args:
                tmp = FormulaNode._rebuild(arg, ptr_map, done_map)
                if isinstance(tmp, FormulaNode):
                    depth = max(tmp.depth + 1, depth)
                args.append(tmp)
            return FormulaNode(formula.op, formula.name, formula.size, depth, tuple(args))

    @staticmethod
    def ptr_constraints_to_ptr_map(ptr_constraints):
        """
        return the dictionary with items (ptr_addr, (being_concretized_symbol, const_node))
        """
        ptr_map = dict()
        for c in ptr_constraints:
            symbol = FormulaNode.get_formula_tree(c.args[0])
            value = FormulaNode.get_depth_1_node(c.args[1])
            ptr_map[value.name] = (symbol, value)
        return ptr_map

    @staticmethod
    def rebuild_formula_without_concretization(formula, ptr_map, done_map):
        """
        The root node
        see FormulaNode.ptr_constraints_to_ptr_map
        the transfer map (a block can have multiple formulas, reuse it)
        """
        if formula is None:
            return None
        # this should be a recursive process
        return FormulaNode._rebuild(formula, ptr_map, done_map)

