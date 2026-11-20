# Log the DLL's rift-match source position at each 0x54000 symbol.
# At RVA 0x464B9 (GetCharsConst call), [esp] = source_pos, esi = combined pos.
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

class RiftPos(gdb.Breakpoint):
    def __init__(self, addr):
        super(RiftPos, self).__init__("*%#x" % addr, internal=False,
                                      type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        pos = int(gdb.parse_and_eval("$esi"))
        src = int(gdb.parse_and_eval("*(unsigned long*)($esp)"))
        g["n"] += 1
        if lo <= pos <= hi and g["n"] < 4000:
            gdb.write("RIFTPOS combined=%d out=%d src=%d delta=%d\n" %
                      (pos, pos - 49544, src, src - pos))
        return False

gdb.write("base=%08x lo=%d hi=%d\n" % (base, lo, hi))
if base:
    RiftPos(base + 0x464B9)
end
continue
