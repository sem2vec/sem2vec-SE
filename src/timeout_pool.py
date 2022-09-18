# -*- coding: utf-8 -*-

import os
import sys
from multiprocessing import Process
import time
import psutil


class TimeoutPool:

    def __init__(self, process, timeout, memory_limit):
        self.ps = []
        self.process = process
        self.timeout = timeout
        self.memory_limit = memory_limit

    @staticmethod
    def meta_print(pid, meta):
        print("run %d : %s" % (pid, meta['args']), file=sys.stdout)

    @staticmethod
    def meta_timeout_print(pid, meta):
        print("timeout %d : %s" % (pid, meta['args']), file=sys.stderr)

    @staticmethod
    def meta_too_much_mem_print(pid, meta):
        rss = TimeoutPool.get_memory_rss(pid)
        print("too much mem %d (mem=%d) : %s" % (pid, rss, meta['args']), file=sys.stderr)

    @staticmethod
    def meta_builder(pid, args):
        return {'pid': pid, 'args': args}

    @staticmethod
    def kill_process(p, wait_for_end=1.0):
        p.terminate()
        # p.kill()
        p.join(wait_for_end)
        if p.exitcode is None:
            # force to kill this process
            os.system('kill %d' % p.pid)

    @staticmethod
    def get_memory_rss(pid):
        return psutil.Process(pid).memory_full_info().rss

    def check_memory_usage(self, meta_too_much_mem_print, wait_for_end):
        new_ps = []
        for p_info in self.ps:
            tmp_p, tmp_start, tmp_meta = p_info
            if tmp_p.is_alive():
                tmp_rss = TimeoutPool.get_memory_rss(tmp_p.pid)
                if tmp_rss > self.memory_limit:
                    # kill process with pid and update self.ps
                    if meta_too_much_mem_print:
                        meta_too_much_mem_print(tmp_p.pid, tmp_meta)
                    TimeoutPool.kill_process(p_info[0], wait_for_end)
                else:
                    new_ps.append(p_info)
            else:
                # this process has end
                pass
        self.ps = new_ps

    def check_timeout_process(self, meta_timeout_print, wait_for_end):
        now = time.time()
        new_ps = []
        for p_info in self.ps:
            tmp_p, tmp_start, tmp_meta = p_info
            if tmp_p.is_alive():
                if now - tmp_start > self.timeout:
                    if meta_timeout_print:
                        meta_timeout_print(tmp_p.pid, tmp_meta)
                    TimeoutPool.kill_process(tmp_p, wait_for_end)
                else:
                    new_ps.append(p_info)
            else:
                # this process has end
                pass
        self.ps = new_ps


    def map(self, target, args_list, meta_builder=None, meta_print=None, meta_timeout_print=None, wait_for_end=1.0, check_freq=0.1):
        if meta_builder is None:
            meta_builder = TimeoutPool.meta_builder
            meta_print = TimeoutPool.meta_print
            meta_timeout_print = TimeoutPool.meta_timeout_print
            meta_toomuchmem_print = TimeoutPool.meta_too_much_mem_print

        for args in args_list:
            while len(self.ps) >= self.process:
                self.check_memory_usage(meta_toomuchmem_print, wait_for_end)
                if len(self.ps) < self.process:
                    break

                self.check_timeout_process(meta_timeout_print, wait_for_end)
                if len(self.ps) < self.process:
                    break
                else:
                    time.sleep(check_freq)

            # new process
            p = Process(target=target, args=args)
            p_start = time.time()
            p.start()
            p_meta = meta_builder(p.pid, args)
            self.ps.append((p, p_start, p_meta))
            meta_print(p.pid, p_meta)

        # finish all processes
        while len(self.ps) > 0:
            self.check_memory_usage(meta_toomuchmem_print, wait_for_end)
            if len(self.ps) == 0:
                break

            self.check_timeout_process(meta_timeout_print, wait_for_end)
            if len(self.ps) == 0:
                break
            time.sleep(check_freq)

