# Dump the DLL's OffsetRiftTable entries used by the rift-match copy.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
g = {"n": 0}

class OR(gdb.Breakpoint):
    def __init__(self, addr):
        super(OR, self).__init__("*%#x" % addr, internal=False,
                                 type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        g["n"] += 1
        if g["n"] != 1:
            return False
        obj = int(gdb.parse_and_eval("*(unsigned long*)($ebp-0x48)"))
        st = int(gdb.parse_and_eval("*(unsigned long*)(%d+0x10)" % obj))
        arr = int(gdb.parse_and_eval("*(unsigned long*)(%d+4)" % st))
        gdb.write("OR obj=%08x st=%08x arr=%08x\n" % (obj, st, arr))
        inf = gdb.selected_inferior()
        for i in range(16):
            d = bytes(inf.read_memory(arr + 8*i, 8))
            a = int.from_bytes(d[0:4], "little", signed=True)
            b = int.from_bytes(d[4:8], "little", signed=True)
            gdb.write("  [%d] left=%d off=%d\n" % (i, a, b))
        return False

gdb.write("base=%08x\n" % base)
if base:
    OR(base + 0x464B9)
end
continue
