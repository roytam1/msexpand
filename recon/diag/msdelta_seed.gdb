# Dump the DLL's fully transformed seed buffer at the decompress loop.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
g = {"srcp": 0, "n": 0}

class MR(gdb.Breakpoint):
    def __init__(self, addr):
        super(MR, self).__init__("*%#x" % addr, internal=False,
                                 type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        this = int(gdb.parse_and_eval("$ecx"))
        srcp = int(gdb.parse_and_eval("*(unsigned long*)(%d+48)" % this))
        if srcp and not g["srcp"]:
            g["srcp"] = srcp
            gdb.write("seed srcp=%08x\n" % srcp)
        return False

class Dec(gdb.Breakpoint):
    def __init__(self, addr):
        super(Dec, self).__init__("*%#x" % addr, internal=False)
    def stop(self):
        g["n"] += 1
        if g["n"] != 1 or not g["srcp"]:
            return False
        inf = gdb.selected_inferior()
        p = g["srcp"]
        for off in (0x400, 0x450, 0x45C, 0x460, 0x7800):
            d = bytes(inf.read_memory(p + off, 48))
            gdb.write("SEED @%04X: %s\n" % (off, " ".join("%02X" % b for b in d)))
        self.delete()
        return False

gdb.write("base=%08x\n" % base)
if base:
    MR(base + 0x35E39)   # MapRva to learn the source pointer
    Dec(base + 0x463BD)  # first symbol read in decompress loop
end
continue
