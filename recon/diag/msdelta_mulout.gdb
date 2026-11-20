# Dump each RiftTable passed to RiftTable::Sort (the result of Multiply).
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
g = {"n": 0}

class Srt(gdb.Breakpoint):
    def __init__(self, addr):
        super(Srt, self).__init__("*%#x" % addr, internal=False,
                                  type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        g["n"] += 1
        tbl = int(gdb.parse_and_eval("$ecx"))
        cnt = int(gdb.parse_and_eval("*(unsigned long*)(%d+12)" % tbl))
        gdb.write("MULRESULT #%d tbl=%08x cnt=%lu\n" % (g["n"], tbl, cnt))
        if 0 < cnt < 300:
            inf = gdb.selected_inferior()
            arr = int(gdb.parse_and_eval("*(unsigned long*)(%d+20)" % tbl))
            with open("C:/Users/Roy/AppData/Local/Temp/opencode/pa30harness/mulout%d.bin" % g["n"], "wb") as fh:
                fh.write(bytes(inf.read_memory(arr, 16*cnt)))
            for i in range(min(cnt, 12)):
                d = bytes(inf.read_memory(arr + 16*i, 16))
                a = int.from_bytes(d[:8], "little", signed=True)
                b = int.from_bytes(d[8:], "little", signed=True)
                gdb.write("  [%d] %d -> %d\n" % (i, a, b))
        return False

gdb.write("base=%08x\n" % base)
if base:
    Srt(base + 0x2E962)
end
continue
