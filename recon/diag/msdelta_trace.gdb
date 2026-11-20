# Trace msdelta.dll's pre-blob bit-reader via gdb Python.
# Usage: gdb -q -batch -x msdelta_trace.gdb --args test_delta.exe <delta> <src> <oracle>
set pagination off
set confirm off
set breakpoint pending on
break ApplyDeltaA
run
printf "=== in ApplyDeltaA, installing internal breakpoints ===\n"
python
import gdb
# At the ApplyDeltaA breakpoint $pc == base + RVA(ApplyDeltaA) == base + 0x1A5A0.
base = int(gdb.parse_and_eval("$pc")) - 0x1A5A0
gdb.write("pc=%08x msdelta base = 0x%08x\n" % (int(gdb.parse_and_eval("$pc")), base))

class TraceBp(gdb.Breakpoint):
    def __init__(self, rva, name):
        super(TraceBp, self).__init__("*%#x" % (base + rva), internal=False,
                                      type=gdb.BP_HARDWARE_BREAKPOINT)
        self.name = name
        gdb.write("installed %s at %08x\n" % (name, base + rva))
    def stop(self):
        a2 = int(gdb.parse_and_eval("*(unsigned long*)($esp+4)"))
        this = int(gdb.parse_and_eval("$ecx"))
        rp  = int(gdb.parse_and_eval("*(unsigned long*)(%d+20)" % a2))
        bc  = int(gdb.parse_and_eval("*(unsigned long*)(%d+40)" % a2))
        cache = int(gdb.parse_and_eval("*(unsigned long*)(%d+8)" % a2))
        gdb.write("%-10s this=%08x a2=%08x rp=%08x bc=%3d cache=%08x\n" %
                  (self.name, this, a2, rp, bc, cache))
        return False

if base is not None:
    TraceBp(0x2DB30, "PEINFO")     # PortableExecutableInfo::InternalFromBitReader
    TraceBp(0x2E760, "RIFT")       # RiftTable::InternalFromBitReader
    TraceBp(0x33A70, "CLIMETA")    # CliMetadata::InternalFromBitReader
    TraceBp(0x4F5F0, "INTFMT")     # IntFormat::InternalFromBitReader
end
continue
