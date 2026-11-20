# Trace IntFormat::ReadNumber values/bit usage in the real msdelta.dll.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb
pc = int(gdb.parse_and_eval("$pc"))
base = pc - 0x1A5A0
g = {"n": 0}
gdb.write("base=%08x\n" % base)

class RNExit(gdb.Breakpoint):
    def __init__(self, addr, n, a2, bc0, cache0):
        super(RNExit, self).__init__("*%#x" % addr, internal=True)
        self.n, self.a2, self.bc0, self.cache0 = n, a2, bc0, cache0
    def stop(self):
        eax = int(gdb.parse_and_eval("$eax"))
        edx = int(gdb.parse_and_eval("$edx"))
        bc = int(gdb.parse_and_eval("*(unsigned long*)(%d+40)" % self.a2))
        val = eax | (edx << 32)
        signed = val - (1 << 64) if val >= (1 << 63) else val
        gdb.write("RN[%3d] val=%d bc=%2d->%2d cache0=%08x\n" %
                  (self.n, signed, self.bc0, bc, self.cache0))
        self.delete()
        return False

class RN(gdb.Breakpoint):
    def __init__(self, addr):
        super(RN, self).__init__("*%#x" % addr, internal=False,
                                 type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        g["n"] += 1
        a2 = int(gdb.parse_and_eval("*(unsigned long*)($esp+4)"))
        bc = int(gdb.parse_and_eval("*(unsigned long*)(%d+40)" % a2))
        rp = int(gdb.parse_and_eval("*(unsigned long*)(%d+20)" % a2))
        cache = int(gdb.parse_and_eval("*(unsigned long*)(%d+8)" % a2))
        ret = int(gdb.parse_and_eval("*(unsigned long*)($esp)"))
        gdb.write("RN-in[%3d] rp=%08x bc=%3d cache=%08x\n" % (g["n"], rp, bc, cache))
        RNExit(ret, g["n"], a2, bc, cache)
        return False

class FBF(gdb.Breakpoint):
    def __init__(self, addr):
        super(FBF, self).__init__("*%#x" % addr, internal=False,
                                  type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        a2 = int(gdb.parse_and_eval("*(unsigned long*)($esp+4)"))
        rp = int(gdb.parse_and_eval("*(unsigned long*)(%d+20)" % a2))
        bc = int(gdb.parse_and_eval("*(unsigned long*)(%d+40)" % a2))
        gdb.write("FBF-start rp=%08x bc=%d\n" % (rp, bc))
        return False

if base:
    FBF(base + 0x2E464)   # RiftTable::FromBitReaderWithFormat
    RN(base + 0x4F9A7)    # IntFormat::ReadNumber
end
continue
