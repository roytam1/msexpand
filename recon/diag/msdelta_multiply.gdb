# Dump both RiftTables passed to RiftTable::Multiply.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
g = {"n": 0}

def dump(tag, tbl):
    cnt = int(gdb.parse_and_eval("*(unsigned long*)(%d+12)" % tbl))
    gdb.write("%s tbl=%08x cnt=%lu\n" % (tag, tbl, cnt))
    if not (0 < cnt <= 200):
        return
    inf = gdb.selected_inferior()
    arr = int(gdb.parse_and_eval("*(unsigned long*)(%d+20)" % tbl))
    for i in range(min(cnt, 12)):
        d = bytes(inf.read_memory(arr + 16*i, 16))
        a = int.from_bytes(d[:8], "little", signed=True)
        b = int.from_bytes(d[8:], "little", signed=True)
        gdb.write("  [%d] %d -> %d\n" % (i, a, b))

class Mul(gdb.Breakpoint):
    def __init__(self, addr):
        super(Mul, self).__init__("*%#x" % addr, internal=False,
                                  type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        g["n"] += 1
        if g["n"] > 4:
            return False
        a = int(gdb.parse_and_eval("$ecx"))
        b = int(gdb.parse_and_eval("$edx"))
        gdb.write("MULTIPLY #%d a=%08x b=%08x\n" % (g["n"], a, b))
        dump(" A", a)
        dump(" B", b)
        return False

gdb.write("base=%08x\n" % base)
if base:
    Mul(base + 0x2F2EC)   # RiftTable::Multiply
end
continue
