import angr
from angr import ExplorationTechnique
from angr.state_plugins.plugin import SimStatePlugin
from angr.state_plugins.solver import SimSolver
from angr.sim_options import UNDER_CONSTRAINED_SYMEXEC, SYMBOL_FILL_UNCONSTRAINED_MEMORY, \
    SYMBOL_FILL_UNCONSTRAINED_REGISTERS, LAZY_SOLVES, ABSTRACT_MEMORY
import z3
import claripy
from claripy.backends.backend_z3 import BackendZ3
import copy
# import angr.storage.memory_mixins.address_concretization_mixin
from src.utils import log, get_section_range


class MemAddrPlugin(SimStatePlugin):
    """
    This plugin needs to modify angr, and the modification is different for angr8 and angr9,
    see function self.get_relative_symbol and self.record_additional_constraint
    """

    def merge(self, _others, _merge_conditions, _common_ancestor=None):
        return False

    def widen(self, _others):
        log.warning("Widening not implemented widen for %s" % self.__class__.__name__)

    def __init__(self):
        super(MemAddrPlugin, self).__init__()
        self.mem_ptr_symbols = set()
        self.mem_ptr_symbols_str = set()
        self.additional_constraints = []

    def has(self, bvs):
        return bvs in self.mem_ptr_symbols

    def get_relative_symbol(self, expr):
        """
        For angr8, in angr.state_plugins.symbolic_memory
        Around line 189
        modify it
            if a is not None:
                if hasattr(self.state, 'memaddr'):
                    self.state.memaddr.get_relative_symbol(e)
                return a

        :param expr: The expr should be concretized to a memory address. We get all symbols being used.
        The symbols may be in 2 types:
        1. a memory address pointer
        2. a offset relative value
        Currently I hope the offset should be relatively small. Usually the offset is a constant.
        We only analyze the simplest a +/- b expression, since it is easy to decide which one is the pointer,
        and this should cover almost all cases
        :return:
        """
        if hasattr(expr, 'depth'):
            if expr.depth == 1 and expr.symbolic:
                # expr itself is a symbolic value, and it is used as a mem ptr
                self.mem_ptr_symbols.add(expr)
            elif expr.depth == 2 and expr.symbolic:
                if expr.op in {'__add__', '__sub__'} and len(expr.args) == 2:
                    if expr.args[0].symbolic and not expr.args[1].symbolic:
                        # args[1] should be a BVV, and its value should be relatively small (a offset)
                        self.mem_ptr_symbols.add(expr.args[0])
                        self.mem_ptr_symbols_str.add(str(expr.args[0]))
                    elif not expr.args[0].symbolic and expr.args[1].symbolic:
                        self.mem_ptr_symbols.add(expr.args[1])
                        self.mem_ptr_symbols_str.add(str(expr.args[1]))
                    else:
                        # 2 symbolic values
                        self.mem_ptr_symbols.add(expr)
                        self.mem_ptr_symbols_str.add(str(expr))
                elif expr.op in {'__add__', '__sub__'} and len(expr.args) == 1:
                    # I guess it is an error of angr, skip it now, simply treat it as a bitvec
                    self.mem_ptr_symbols.add(expr.args[0])
                    self.mem_ptr_symbols_str.add(str(expr.args[0]))
                else:
                    log.error('Unsolvable expression for concretizing memory address %s' % str(expr))
                    self.mem_ptr_symbols.add(expr)
                    self.mem_ptr_symbols_str.add(str(expr))
                    # raise NotImplementedError()
            else:
                # It could be a very complex formula. 'If' condition is often in it, so we treat the whole formula as
                # an input, since it is usually not being simplified.
                tmp = claripy.simplify(expr)
                # we must simplify it. It seems the simplify of claripy merely sort the AST in an order
                self.mem_ptr_symbols.add(tmp)
                self.mem_ptr_symbols_str.add(str(tmp))

    def record_additional_constraint(self, constraint):
        """
        For angr9
        in angr/storage/memory_mixins/address_concretization_mixin.py
        In function AddressConcretizationMixin._apply_concretization_strategies (do the same as above)
        or in functions AddressConcretizationMixin.store and load
        under if not trival, modify
        if not trival:
            ...
            if hasattr(self.state, 'memaddr'):
                conditional_constraint = claripy.simplify(conditional_constraint)
                self.state.memaddr.record_additional_constraint(conditional_constraint)
            self._add_constraints(conditional_constraint, condition=condition, **kwargs)
        """
        self.additional_constraints.append(constraint)

    def copy(self, _memo):
        m = MemAddrPlugin()
        m.mem_ptr_symbols = self.mem_ptr_symbols.copy()
        m.mem_ptr_symbols_str = self.mem_ptr_symbols_str.copy()
        m.additional_constraints = self.additional_constraints.copy()
        return m


class ITEPlugin(SimStatePlugin):
    """
    To use this plugin, modify
    angr\engines\vex\claripy\datalayer.py
    in function _perform_vex_expr_ITE (around line 98)
    insert following code
            if hasattr(self.state, 'itep'):
            # false branch
            self.state.itep.add_branch(self.state, cond == 0, ifFalse)
            # true constraint
            self.state.solver.constraints.append(cond != 0)
            self.state.solver.reload_solver()
            # return true branch
            return ifTrue
    """

    def __init__(self):
        super(ITEPlugin, self).__init__()
        # a block can have multiple ITE statements
        # fork states at ITE with additional constraints
        self._states = []

    def merge(self, _others, _merge_conditions, _common_ancestor=None):
        return False

    def widen(self, _others):
        log.warning("Widening not implemented widen for %s" % self.__class__.__name__)

    def add_branch(self, state, cond, val):
        new_state = state.copy()
        new_state.solver.constraints.append(cond)
        new_state.solver.reload_solver()
        self._states.append((state.copy(), cond, val))

    def has_branch(self):
        return len(self._states) > 0

    def copy(self, _memo):
        itep = ITEPlugin()
        itep._states = self._states.copy()
        return itep


class TraceInCalleeLengthPlugin(SimStatePlugin):
    """
    This plugin merely used for limit the length of trace in a callee
    When it is too long, we simply end the trace
    """
    def __init__(self):
        super(TraceInCalleeLengthPlugin, self).__init__()
        self.from_callee_entry = 0

    @property
    def length_in_callee(self):
        return self.from_callee_entry

    def add_step(self, n=1):
        self.from_callee_entry += n

    def reset(self):
        self.from_callee_entry = 0

    def merge(self, _others, _merge_conditions, _common_ancestor=None):
        return False

    def widen(self, _others):
        log.warning("Widening not implemented widen for %s" % self.__class__.__name__)

    def copy(self, _memo):
        tmp = TraceInCalleeLengthPlugin()
        tmp.from_callee_entry = self.from_callee_entry
        return tmp


plugin_map = {
    'memaddr': MemAddrPlugin,
    'itep': ITEPlugin,
    'callee_limiter': TraceInCalleeLengthPlugin,
}


# add timeout function for solver
# in claripy/backends/backend_z3.py, line 768
# add `solver.set('timeout', 3 * 1000)`
# timeout if the solver costs more than 3 seconds


def symbolize_section(p, s, sec_name):
    sec_range = get_section_range(p, sec_name)
    for addr in sec_range:
        if s.mem[addr].byte.concrete == 0:
            # symbolize zero bytes
            s.mem[addr].byte = claripy.BVS('mem_%x' % addr, 8)


def symbolize_bss_sections(p, s):
    # find all bss sections (sections with name in pattern .bss*)
    section_map = p.loader.main_object.sections_map
    for sec_name in section_map:
        if sec_name.startswith('.bss'):
            symbolize_section(p, s, sec_name)


def create_blank_state(p, addr, add_plugins=[]) -> angr.SimState:
    plugins = dict()
    for plug in add_plugins:
        if plug in plugin_map.keys():
            plugins[plug] = plugin_map[plug]()
    # s = p.factory.blank_state(addr=addr, plugins=plugins, add_options={UNDER_CONSTRAINED_SYMEXEC})
    options = {SYMBOL_FILL_UNCONSTRAINED_MEMORY, SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    if angr.__version__[0] == 8:
        options = {SYMBOL_FILL_UNCONSTRAINED_MEMORY, SYMBOL_FILL_UNCONSTRAINED_REGISTERS, UNDER_CONSTRAINED_SYMEXEC}
    elif angr.__version__[0] == 9:
        options = {SYMBOL_FILL_UNCONSTRAINED_MEMORY, SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    else:
        options = {SYMBOL_FILL_UNCONSTRAINED_MEMORY, SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    s = p.factory.blank_state(addr=addr, plugins=plugins, add_options=options)
    # symbolize_bss_sections(p, s)
    return s
