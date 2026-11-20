# Dump the DLL's per-byte hint buffer from AbstractRiftHintTransformComponent::MapRva.
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
        if g["n"] > 100000:
            return False
        this = int(gdb.parse_and_eval("$ecx"))
        hp = int(gdb.parse_and_eval("*(unsigned long*)(%d+80)" % this))
        hn = int(gdb.parse_and_eval("*(unsigned long*)(%d+84)" % this))
        if not hp:
            return False
        gdb.write("HINT this=%08x ptr=%08x len=%lu\n" % (this, hp, hn))
        if 0 < hn < 200000:
            inf = gdb.selected_inferior()
            raw = bytes(inf.read_memory(hp, hn))
            with open("C:/Users/Roy/AppData/Local/Temp/opencode/pa30harness/dllhint.bin", "wb") as fh:
                fh.write(raw)
            # summarize bits set
            from collections import Counter
            c = Counter(raw)
            gdb.write("HINT bits: %s\n" % ", ".join("%02X:%d" % (k,v) for k,v in sorted(c.items())[:8]))
        return False

gdb.write("base=%08x\n" % base)
if base:
    MR(base + 0x35E39)
end
continue
