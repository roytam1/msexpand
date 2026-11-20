# Log source position for non-rift matches: at RVA 0x48352 the argument to
# GetCharsConst is (combined_pos - distance). Break at the call and read [esp].
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb, os
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
lo = int(os.environ.get("SYM_LO", "0"))
hi = int(os.environ.get("SYM_HI", "100000"))
g = {"n": 0}

class Src(gdb.Breakpoint):
    def __init__(self, addr):
        super(Src, self).__init__("*%#x" % addr, internal=False,
                                  type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        g["n"] += 1
        src = int(gdb.parse_and_eval("*(unsigned long*)($esp)"))
        pos = int(gdb.parse_and_eval("$esi")) - 49544
        if lo <= pos <= hi and g["n"] < 100000:
            gdb.write("MATCHSRC out=%d src=%d\n" % (pos, src))
        return False

gdb.write("base=%08x\n" % base)
if base:
    Src(base + 0x48352)
end
continue
