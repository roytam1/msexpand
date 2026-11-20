# Dump the RiftTable passed to OffsetRiftTable::Init in the decompress path.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
g = {"n": 0}

class Init(gdb.Breakpoint):
    def __init__(self, addr):
        super(Init, self).__init__("*%#x" % addr, internal=False,
                                   type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        g["n"] += 1
        if g["n"] > 3:
            return False
        this = int(gdb.parse_and_eval("$ecx"))
        tbl = int(gdb.parse_and_eval("*(unsigned long*)($esp+4)"))
        cnt = int(gdb.parse_and_eval("*(unsigned long*)(%d+12)" % tbl))
        gdb.write("INIT this=%08x tbl=%08x cnt=%lu\n" % (this, tbl, cnt))
        inf = gdb.selected_inferior()
        arr = int(gdb.parse_and_eval("*(unsigned long*)(%d+20)" % tbl))
        with open("C:/Users/Roy/AppData/Local/Temp/opencode/pa30harness/orift_table.bin", "wb") as fh:
            fh.write(bytes(inf.read_memory(arr, 16*cnt)))
        for i in range(min(cnt, 100)):
            d = bytes(inf.read_memory(arr + 16*i, 16))
            a = int.from_bytes(d[:8], "little", signed=True)
            b = int.from_bytes(d[8:], "little", signed=True)
            gdb.write("  [%d] %d -> %d (rift=%d)\n" % (i, a, b, b-a))
        return False

gdb.write("base=%08x\n" % base)
if base:
    Init(base + 0x3A2C2)   # OffsetRiftTable::Init
end
continue
