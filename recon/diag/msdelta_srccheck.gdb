# At RVA 0x46660 (right after GetCharsConst), EAX = source pointer.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
g = {"n": 0}

class GC(gdb.Breakpoint):
    def __init__(self, addr):
        super(GC, self).__init__("*%#x" % addr, internal=False,
                                 type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        g["n"] += 1
        ptr = int(gdb.parse_and_eval("$eax"))
        out = int(gdb.parse_and_eval("$esi")) - 49544
        inf = gdb.selected_inferior()
        d = bytes(inf.read_memory(ptr, 8))
        if 83690 <= out <= 83705:
            gdb.write("SRCPTR out=%d ptr=%08x bytes=%s\n" %
                      (out, ptr, " ".join("%02X" % b for b in d)))
        return False

gdb.write("base=%08x\n" % base)
if base:
    GC(base + 0x46660)
end
continue
