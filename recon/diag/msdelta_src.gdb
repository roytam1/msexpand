# Dump the DLL's source-buffer bytes around a file offset by breaking where
# BufferList::GetChars returns a pointer into the (transformed) source.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb, os
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
want = int(os.environ.get("SRC_OFF", "1024"))
src_len = 49544
g = {"n": 0}

class Src(gdb.Breakpoint):
    def __init__(self, addr):
        super(Src, self).__init__("*%#x" % addr, internal=False,
                                  type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        pos = int(gdb.parse_and_eval("$esi"))
        ptr = int(gdb.parse_and_eval("$eax"))
        if pos < src_len and g["n"] < 6:
            g["n"] += 1
            inf = gdb.selected_inferior()
            data = bytes(inf.read_memory(ptr, 32))
            gdb.write("GETCHARS pos=%d ptr=%08x bytes=%s\n" %
                      (pos, ptr, " ".join("%02X" % b for b in data)))
        return False

gdb.write("base=%08x want=%d\n" % (base, want))
if base:
    Src(base + 0x46389)   # after BufferList::GetChars
end
continue
