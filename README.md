# sem2vec
Find some useful information from https://sites.google.com/view/sem2vec

# Install python packages
```
pip install angr networkx pandas numpy sklearn tqdm lark matplotlib
```
Or you could run `pip install -r requirements.txt`, but some packages maybe outdated. I recommand you to install the latest angr.

Then follow the official instruction to install pytorch and dgl

# Modify package codes
Use angr (ver 9.**)

In file sem2vec-env/lib/site-packages/angr/procedures/posix/poll.py

Modify line 42 (the select has no attribute POLLIN, angr bugs)
```
            # if events & select.POLLIN and fd >= 0:
            #     revents = pollfd["revents"][self.arch.sizeof["short"]-1:1].concat(self.state.solver.BVS('fd_POLLIN', 1))
            #     self.state.memory.store(fds + offset * size_of_pollfd + offset_revents, revents, endness=self.arch.memory_endness)

            if events and fd >= 0:
                revents = pollfd["revents"][self.arch.sizeof["short"]-1:1].concat(self.state.solver.BVS('fd_POLLIN', 1))
                self.state.memory.store(fds + offset * size_of_pollfd + offset_revents, revents, endness=self.arch.memory_endness)
```
In file sem2vec-env/lib/site-packages/angr/storage/memory_mixins/address_concretization_mixin.py

In functions AddressConcretizationMixin.store and load, under if not trival, modify
```
        if not trivial:
            # apply the concretization results to the state
            constraint_options = [addr == concrete_addr for concrete_addr in concrete_addrs]
            conditional_constraint = self.state.solver.Or(*constraint_options)
            # sem2vec
            if hasattr(self.state, 'memaddr'):
                conditional_constraint = claripy.simplify(conditional_constraint)
                self.state.memaddr.record_additional_constraint(conditional_constraint)
            # sem2vec
            self._add_constraints(conditional_constraint, condition=condition, **kwargs)
```
It is necessary to modify some procedures of angr, to make sure the USE can run smoothly.

In file sem2vec-env/lib/site-packages/angr/procedures/libc

Modify classes in fprintf.py
```
class fprintf(FormatParser):

    def run(self, file_ptr):
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return -1
        # sem2vec
        return 0
```

Modify classes in printf.py
```
class printf(FormatParser):
    def run(self):
        stdout = self.state.posix.get_fd(1)
        if stdout is None:
            return -1
        # sem2vec
        return 0

class __printf_chk(FormatParser):
    def run(self):
        stdout = self.state.posix.get_fd(1)
        if stdout is None:
            return -1
        # sev2vec
        return 0
```

This is optional.

In file sem2vec-env/lib/site-packages/claripy/backends/backend_z3.py

in function BackendZ3._satisfiable
```
    def _satisfiable(self, extra_constraints=(), solver=None, model_callback=None):
        global solve_count
        # sem2vec
        solver.set('timeout', 3 * 1000)
        # sem2vec
        solve_count += 1
        if len(extra_constraints) > 0:
```

# Download sample binaries
`mkdir -p samples & cd samples`

Then download the zip file from https://drive.google.com/file/d/17EVsS2ff7IMheYO_MllXU23aBLVLk_6G/view?usp=sharing , unzip it.

# Collect symbolic tracelets
```
# run on coreutils
bash ./scripts/collect_coreutils_batch.sh

# run on binutils
bash ./scripts/collect_binutils_batch.sh
```

# Get inputs for model
```
# run on coreutils
bash ./scripts/coreutils_nx_graphs_batch.sh

# run on binutils
bash ./scripts/binutils_nx_graphs_batch.sh
```

# Build dataset for formula embedding
```
# this is the script to build dataset on coreutils compiled with gcc -O0 and gcc -O3
bash ./build_sameline_dataset.sh
```

