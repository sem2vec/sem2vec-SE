from angr import ExplorationTechnique


class SimExeUntilTech(ExplorationTechnique):

    def __init__(self, until_func, tmp_finish_stash='tmpfinish'):
        super(SimExeUntilTech, self).__init__()
        self._until_func = until_func
        self._tmp_finish_stash = tmp_finish_stash

    def get_tmp_finish_stash_str(self):
        return self._tmp_finish_stash

    def step_state(self, simgr, state, **kwargs):
        if self._until_func(state):
            # do not execute it, keep itself
            return {self._tmp_finish_stash: [state]}
        else:
            return simgr.step_state(state)


class LoopLimiterTech(ExplorationTechnique):

    def __init__(self, inloop_stash='inloop'):
        super(LoopLimiterTech, self).__init__()
        self._inloop_stash = inloop_stash

    def get_in_loop_stash_str(self):
        return self._inloop_stash

    @staticmethod
    def tail_loop_occurrence(unit, trace, bound):
        unit_len = len(unit)
        trace_len = len(trace)
        for i in range(bound):
            e_idx = trace_len - i * unit_len
            b_idx = e_idx - unit_len
            if b_idx < 0 or trace[b_idx:e_idx] != unit:
                return False
        return True

    @staticmethod
    def in_loop(state):
        cur = state.addr
        # we do not treat it strictly, only see if cur occurred repeatedly
        history = list(state.history.bbl_addrs)
        same_idxs = []
        for idx in range(len(history)):
            if history[idx] == cur:
                same_idxs.append(idx)
        count = len(same_idxs)

        if count > 2:
            for loop_split in range(1, count // 3):
                loop_unit = history[same_idxs[0 - loop_split]:]
                if LoopLimiterTech.tail_loop_occurrence(loop_unit, history[:-len(loop_unit)], 6):
                    return True
        return False

    @staticmethod
    def get_state_loop_unit(state):
        cur = state.addr
        # we do not treat it strictly, only see if cur occurred repeatedly
        history = list(state.history.bbl_addrs)
        same_idxs = []
        for idx in range(len(history)):
            if history[idx] == cur:
                same_idxs.append(idx)
        count = len(same_idxs)

        if count > 2:
            for loop_split in range(1, count // 3):
                loop_unit = history[same_idxs[0 - loop_split]:]
                if LoopLimiterTech.tail_loop_occurrence(loop_unit, history[:-len(loop_unit)], 6):
                    return loop_unit
        return None

    def step_state(self, simgr, state, **kwargs):
        if self.in_loop(state):
            return {self._inloop_stash: [state]}
        else:
            return simgr.step_state(state)


class SkipMeaninglessBlockConstraintsTech(ExplorationTechnique):

    def __init__(self, is_meaningless_state):
        super(SkipMeaninglessBlockConstraintsTech, self).__init__()
        self._is_meaningless_state = is_meaningless_state

    def step_state(self, simgr, state, **kwargs):
        if self._is_meaningless_state(state):
            pre_cs = state.solver.constraints.copy()
            stashes = simgr.step_state(state)
            for s in stashes[None]:
                s.solver.constraints.clear()
                s.solver.constraints.extend(pre_cs)
            return stashes
        else:
            return simgr.step_state(state)


class TraceletInCalleeLimiter(ExplorationTechnique):
    def __init__(self, callee_trace_max_len, finish_stash='toolongincallee'):
        super(TraceletInCalleeLimiter, self).__init__()
        self.callee_trace_max_len = callee_trace_max_len
        self.finish_stash = finish_stash

    def step_state(self, simgr, state, **kwargs):
        stashes = simgr.step_state(state)
        new_stashes = dict()
        for k in stashes:
            new_stashes[k] = []
            for s in stashes[k]:
                if len(s.callstack) > 1:
                    s.callee_limiter.add_step(n=1)
                else:
                    s.callee_limiter.reset()
                if s.callee_limiter.length_in_callee >= self.callee_trace_max_len:
                    if self.finish_stash not in new_stashes:
                        new_stashes[self.finish_stash] = []
                    new_stashes[self.finish_stash].append(s)
                else:
                    new_stashes[k].append(s)
        return new_stashes


class TraceletCollectionTech(ExplorationTechnique):

    def __init__(self, is_end_state, is_meaningless_state, is_inloop, finish_stash='finish', inloop_stash='inloop'):
        super(TraceletCollectionTech, self).__init__()
        self._is_end = is_end_state
        self._is_meaningless = is_meaningless_state
        self._is_inloop = is_inloop

        self.finish_stash = finish_stash
        self.inloop_stash = inloop_stash

    def step_state(self, simgr, state, **kwargs):
        if self._is_end(state):
            return {self.finish_stash: [state]}
        elif self._is_inloop(state):
            return {self.inloop_stash: [state]}
        elif self._is_meaningless(state):
            # do not collect the constraints on this block
            pre_cs = state.solver.constraints.copy()
            stashes = simgr.step_state(state)
            for s in stashes[None]:
                s.solver.constraints.clear()
                s.solver.constraints.extend(pre_cs)
            return stashes
        else:
            stashes = simgr.step_state(state)
            # tmp = []
            # for k in stashes.keys():
            #     for s in stashes[k]:
            #         if s.itep.has_branch():
            #             for tmp_branch_s, cond, val in s.itep._states:
            #                 new_tmp_state = state.copy()
            #                 new_tmp_state.solver.constraints.append(cond)
            #                 new_tmp_state.solver.reload_solver()
            #                 tmp_stashes = simgr.step_state(new_tmp_state)
            #                 tmp.append(tmp_stashes)
            # for k in stashes.keys():
            #     for tmp_s in tmp:
            #         stashes[k].extend(tmp_s[k])
            return stashes


class SkipCalleesTech(ExplorationTechnique):

    def __init__(self, func_range):
        super(SkipCalleesTech, self).__init__()
        self.func_range = func_range

    def step_state(self, simgr, state, **kwargs):
        if len(state.callstack) < 2:
            return simgr.step_state(state)
        else:
            # may be a recursive function
            # simply check and goto the first call's return address
            for _call in state.callstack:
                if _call.ret_addr in self.func_range:
                    state.regs.rip = _call.ret_addr
                    return simgr.step_state(state)
                break
            raise NotImplementedError('Unknown situation for callstack!')
