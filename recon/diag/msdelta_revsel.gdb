# Log Reverse's extra-add selection state at RVA 0x2F15F.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
g = {"n": 0}

def s64(lo, hi):
    v = lo | (hi << 32)
    return v - (1 << 64) if v >= (1 << 63) else v

class RA(gdb.Breakpoint):
    def __init__(self, addr):
        super(RA, self).__init__("*%#x" % addr, internal=False,
                                 type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        g["n"] += 1
        if g["n"] > 30:
            return False
        a0 = int(gdb.parse_and_eval("*(unsigned long*)($esp)"))
        a1 = int(gdb.parse_and_eval("*(unsigned long*)($esp+4)"))
        a2 = int(gdb.parse_and_eval("*(unsigned long*)($esp+8)"))
        a3 = int(gdb.parse_and_eval("*(unsigned long*)($esp+12)"))
        # offset = [ebp-0x3C] low, [ebp-0x40] high
        o0 = int(gdb.parse_and_eval("*(unsigned long*)($ebp-0x3C)"))
        o1 = int(gdb.parse_and_eval("*(unsigned long*)($ebp-0x40)"))
        gdb.write("SEL n=%d left=%d right=%d off=%d ebx=%08x\n" %
                  (g["n"], s64(a0,a1), s64(a2,a3), s64(o0,o1),
                   int(gdb.parse_and_eval("$ebx"))))
        return False

gdb.write("base=%08x\n" % base)
if base:
    RA(base + 0x2F15F)
end
continue
