# Dump the DLL's IntFormat Huffman length tables at RiftTable::FromBitReaderWithFormat.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
g = {"n": 0}

class FB(gdb.Breakpoint):
    def __init__(self, addr):
        super(FB, self).__init__("*%#x" % addr, internal=False,
                                 type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        g["n"] += 1
        if g["n"] > 2:
            return False
        f1 = int(gdb.parse_and_eval("*(unsigned long*)($esp+8)"))
        f2 = int(gdb.parse_and_eval("*(unsigned long*)($esp+12)"))
        for tag, f in (("f1", f1), ("f2", f2)):
            lp = int(gdb.parse_and_eval("*(unsigned long*)(%d+24)" % f))
            inf = gdb.selected_inferior()
            data = bytearray(inf.read_memory(lp, 252))
            lens = [str(x) for x in data]
            cp = int(gdb.parse_and_eval("*(unsigned long*)(%d+28)" % f))
            codes = [int.from_bytes(bytes(inf.read_memory(cp + 4*i, 4)), "little")
                     for i in (0, 24, 26, 27, 36, 145, 147, 148, 151)]
            gdb.write("%s lens (#%d): %s\n" % (tag, g["n"], " ".join(lens)))
            gdb.write("%s codes (#%d): %s\n" % (tag, g["n"], codes))
        return False

if base:
    FB(base + 0x2E464)   # RiftTable::FromBitReaderWithFormat
end
continue
