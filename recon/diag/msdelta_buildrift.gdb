# Log RiftTable::Add/AddNonZero calls and the table passed to OffsetRiftTable::Init.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb, os
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
g = {"n": 0}

def s64(lo, hi):
    v = lo | (hi << 32)
    return v - (1 << 64) if v >= (1 << 63) else v

class Add(gdb.Breakpoint):
    def __init__(self, addr, name):
        super(Add, self).__init__("*%#x" % addr, internal=False,
                                  type=gdb.BP_HARDWARE_BREAKPOINT)
        self.name = name
    def stop(self):
        this = int(gdb.parse_and_eval("$ecx"))
        a = int(gdb.parse_and_eval("*(unsigned long*)($esp+4)"))
        b = int(gdb.parse_and_eval("*(unsigned long*)($esp+8)"))
        c = int(gdb.parse_and_eval("*(unsigned long*)($esp+12)"))
        d = int(gdb.parse_and_eval("*(unsigned long*)($esp+16)"))
        left, right = s64(a,b), s64(c,d)
        ret = int(gdb.parse_and_eval("*(unsigned long*)($esp)")) - base
        gdb.write("%s this=%08x caller=%06X %d -> %d\n" %
                  (self.name, this, ret, left, right))
        return False

class Init(gdb.Breakpoint):
    def __init__(self, addr):
        super(Init, self).__init__("*%#x" % addr, internal=False,
                                   type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        tbl = int(gdb.parse_and_eval("*(unsigned long*)($esp+4)"))
        cnt = int(gdb.parse_and_eval("*(unsigned long*)(%d+12)" % tbl))
        gdb.write("INIT-TABLE tbl=%08x cnt=%lu\n" % (tbl, cnt))
        return False

gdb.write("base=%08x\n" % base)
if base:
    Add(base + 0x2DF90, "ADD")
    Add(base + 0x360FB, "ADDNZ")
    Init(base + 0x3A2C2)
end
continue
