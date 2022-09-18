"""
Sometimes we need to convert the string of vex IR to a good format for our parser
"""
from src.vex_parser import *


def last_2_statements_are_conditional_jump(raw_stmts: list):
    if len(raw_stmts) < 2:
        return False
    s1 = raw_stmts[-2]
    s2 = raw_stmts[-1]
    return 'if (' in s1 and 'Ijk_Boring' in s1 and 'PUT(rip) = ' in s1 and \
           'Ijk_Boring' in s2 and 'PUT(rip) = ' in s2


def convert_last_2_statements_to_if_else_ip_assignment(raw_stmts: list):
    ret = raw_stmts[:-2]
    ret.append(raw_stmts[-2] + ' else { ' + raw_stmts[-1] + ' }')
    return ret


class CheckThenChange:
    def check(self, stmt: str, insn: str):
        raise NotImplementedError()

    def change(self, stmt: str):
        raise NotImplementedError()


class CheckITE(CheckThenChange):
    def check(self, stmt: str, insn: str):
        # it works for all non-floating-related ITE statements
        # we do not convert statement of floating point relative instruction
        return (not insn.startswith('f')) and ('= ITE(' in stmt)

    def change(self, stmt: str):
        # the raw simple vex ir should be merely 1 function ITE, all 3 args (cond, if-do, else-do) are tmp of constant
        tmp = stmt.strip().split(' = ITE(')
        left_str = tmp[0]
        args_str = tmp[1][:-1]
        tmp = args_str.split(',')
        cond = tmp[0].strip()
        ifdo = left_str + ' = ' + tmp[1].strip()
        elsedo = left_str + ' = ' + tmp[2].strip()
        return "if (%s) { %s } else { %s }" % (cond, ifdo, elsedo)


class CheckMovapsMovdqa(CheckThenChange):
    def check(self, stmt: str, insn: str):
        return (insn.startswith('movaps\t') or insn.startswith('movdqa\t')) and stmt.startswith('if')

    def change(self, stmt: str):
        return None


stmt_level_checks = [
    CheckITE(),
    CheckMovapsMovdqa()
]


def raw_stmt_check_and_modify(raw_stmt: str, asm_insn: str):
    for c in stmt_level_checks:
        if c.check(raw_stmt, asm_insn):
            return c.change(raw_stmt)
    return raw_stmt
