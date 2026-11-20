set pagination off
set confirm off
set breakpoint pending on
catch load msdelta
run
printf "=== loaded ===\n"
break ApplyDeltaA
continue
printf "=== in ApplyDeltaA ===\n"
info registers eax ebx ecx edx esi edi ebp esp
bt 5
