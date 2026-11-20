# Trace CompressionFormat::ReadSymbol return values near a target output pos.
# At RVA 0x463BA: EAX = symbol.length, [ebp-0x84] = symbol.value, esi = combined pos.
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
        pos = int(gdb.parse_and_eval("$esi")) - 49544
        ln = int(gdb.parse_and_eval("$eax"))
        val = int(gdb.parse_and_eval("*(unsigned long*)($ebp-0x84)"))
        g["n"] += 1
        if lo <= pos <= hi and g["n"] < 100000:
            gdb.write("DLLSYM out=%d len=%d val=%lu(0x%lx)\n" %
                      (pos, ln, val & 0xffffffff, val & 0xffffffff))
        return False

gdb.write("base=%08x lo=%d hi=%d\n" % (base, lo, hi))
if base:
    Sym(base + 0x463BD)   # after ReadSymbol
end
continue
