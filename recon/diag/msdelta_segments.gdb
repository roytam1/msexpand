# Dump the source BufferList segment sizes at GetCharsConst entry.
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
        if g["n"] != 1:
            return False
        bl = int(gdb.parse_and_eval("$ecx"))
        cnt = int(gdb.parse_and_eval("*(unsigned long*)(%d+16)" % bl))
        arr = int(gdb.parse_and_eval("*(unsigned long*)(%d+20)" % bl))
        gdb.write("BUFFERLIST bl=%08x cnt=%lu arr=%08x\n" % (bl, cnt, arr))
        inf = gdb.selected_inferior()
        total = 0
        for i in range(min(cnt, 30)):
            bp = int.from_bytes(bytes(inf.read_memory(arr + 4*i, 4)), "little")
            mb = int.from_bytes(bytes(inf.read_memory(bp + 16, 4)), "little")
            size = int.from_bytes(bytes(inf.read_memory(mb + 20, 4)), "little")
            data = int.from_bytes(bytes(inf.read_memory(mb + 16, 4)), "little")
            gdb.write("  seg[%d] bp=%08x mb=%08x size=%lu data=%08x cum=%lu\n" %
                      (i, bp, mb, size, data, total))
            total += size
        gdb.write("  total=%lu\n" % total)
        return False

gdb.write("base=%08x\n" % base)
if base:
    GC(base + 0x4605E)   # GetCharsConst
end
continue
