# Dump the DLL's transform RiftTable via AbstractRiftHintTransformComponent::MapRva.
# this=ECX, a2=[esp+4], a3=[esp+8]; RiftTable ptr at this+6.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
g = {"n": 0}

class MR(gdb.Breakpoint):
    def __init__(self, addr):
        super(MR, self).__init__("*%#x" % addr, internal=False,
                                 type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        g["n"] += 1
        if g["n"] > 3:
            return False
        this = int(gdb.parse_and_eval("$ecx"))
        a2 = int(gdb.parse_and_eval("*(unsigned long*)($esp+4)"))
        a3 = int(gdb.parse_and_eval("*(unsigned long*)($esp+8)"))
        tbl = int(gdb.parse_and_eval("*(unsigned long*)(%d+24)" % this))
        cnt = int(gdb.parse_and_eval("*(unsigned long*)(%d+12)" % tbl))
        gdb.write("MAPRVA this=%08x a2=%lu a3=%lu tbl=%08x cnt=%u\n" %
                  (this, a2, a3, tbl, cnt))
        srcp = int(gdb.parse_and_eval("*(unsigned long*)(%d+48)" % this))
        if srcp:
            inf = gdb.selected_inferior()
            d = bytes(inf.read_memory(srcp + 0x400, 48))
            gdb.write("  SRCBUF=%08x @400: %s\n" %
                      (srcp, " ".join("%02X" % b for b in d)))
        if tbl and 0 < cnt <= 400:
            inf = gdb.selected_inferior()
            arr = int(gdb.parse_and_eval("*(unsigned long*)(%d+20)" % tbl))
            for i in range(min(cnt, 200)):
                d = bytes(inf.read_memory(arr + 16*i, 16))
                left = int.from_bytes(d[:8], "little", signed=True)
                right = int.from_bytes(d[8:], "little", signed=True)
                gdb.write("  [%d] %d -> %d (rift=%d)\n" %
                          (i, left, right, right-left))
        return False

gdb.write("base=%08x\n" % base)
if base:
    MR(base + 0x35E39)   # AbstractRiftHintTransformComponent::MapRva
end
continue
