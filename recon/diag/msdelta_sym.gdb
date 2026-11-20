# Log the DLL's CompressionSymbol stream around a given output position.
# At RVA 0x463BD: EAX=symbol.length, [ebp-0x84]=symbol.value, ESI=output pos.
# Set SYM_LO/SYM_HI in the environment to limit the range.
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
python
import gdb, os
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
lo = int(os.environ.get("SYM_LO", "0"))
hi = int(os.environ.get("SYM_HI", "100000"))
g = {"n": 0}

class Sym(gdb.Breakpoint):
    def __init__(self, addr):
        super(Sym, self).__init__("*%#x" % addr, internal=False,
                                  type=gdb.BP_HARDWARE_BREAKPOINT)
    def stop(self):
        pos = int(gdb.parse_and_eval("$esi"))
        ln = int(gdb.parse_and_eval("$eax"))
        val = int(gdb.parse_and_eval("*(unsigned long*)($ebp-0x84)"))
        if lo <= pos <= hi:
            gdb.write("DLLSYM pos=%d len=%d val=%lu(0x%lx)\n" % (pos, ln, val & 0xffffffff, val & 0xffffffff))
        return False

gdb.write("base=%08x lo=%d hi=%d\n" % (base, lo, hi))
if base:
    Sym(base + 0x463BD)
end
continue
