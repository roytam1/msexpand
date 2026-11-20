# Trace the running offset [ebp-0x40] / [ebp-0x3C] in RiftTable::Reverse's
# negative-right Add path at RVA 0x2F15F.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
g = {"n": 0}

class RA(gdb.Breakpoint):
    def __init__(self, addr):
        super(RA, self).__init__("*%#x" % addr, internal=False,
                                 type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        g["n"] += 1
        if g["n"] > 200:
            return False
        a0 = int(gdb.parse_and_eval("*(unsigned long*)($esp)"))
        a1 = int(gdb.parse_and_eval("*(unsigned long*)($esp+4)"))
        a2 = int(gdb.parse_and_eval("*(unsigned long*)($esp+8)"))
        a3 = int(gdb.parse_and_eval("*(unsigned long*)($esp+12)"))
        c = int(gdb.parse_and_eval("$ecx"))
        gdb.write("REVADD n=%d this=%08x left=%d right=%d\n" %
                  (g["n"], c, (a1 << 32) | a0, (a3 << 32) | a2))
        return False

gdb.write("base=%08x\n" % base)
if base:
    RA(base + 0x2F15F)
end
continue
