$ErrorActionPreference = 'Stop'
$path = '\\roy-xp\c\devel\cabarc\IE6.0SP1-KB2722913-WINDOWS2000-X86-CHT.EXE'
$b = [System.IO.File]::ReadAllBytes($path)
function U16($o) { [int]$b[$o] -bor ([int]$b[$o+1] -shl 8) }
function U32($o) { [int64]$b[$o] -bor ([int64]$b[$o+1] -shl 8) -bor ([int64]$b[$o+2] -shl 16) -bor ([int64]$b[$o+3] -shl 24) }
$offs = @()
for ($i = 0; $i -le $b.Length - 4; $i++) {
    if ($b[$i] -eq 0x4D -and $b[$i+1] -eq 0x53 -and $b[$i+2] -eq 0x43 -and $b[$i+3] -eq 0x46) { $offs += $i }
}
Write-Output "MSCF offsets: $($offs -join ', ')"
foreach ($o in $offs) {
    if ($o + 36 -gt $b.Length) { continue }
    $coff = [int](U32 ($o+16))
    $cFiles = U16 ($o+28)
    $flags = U16 ($o+30)
    $cb = U32 ($o+8)
    Write-Output ("--- CAB at {0}: cb={1} coffFiles=+{2} ({3}) files={4} flags={5:X4}" -f $o, $cb, $coff, ($o+$coff), $cFiles, $flags)
    $p = $o + $coff
    for ($k = 0; $k -lt $cFiles; $k++) {
        if ($p + 16 -gt $b.Length) { Write-Output '  truncated'; break }
        $sz = U32 $p
        $end = $p + 16
        while ($end -lt $b.Length -and $b[$end] -ne 0) { $end++ }
        $name = [System.Text.Encoding]::ASCII.GetString($b, $p+16, [Math]::Min(120, $end-($p+16)))
        Write-Output ("  {0,8}  {1}" -f $sz, $name)
        $p = $end + 1
        if ($k -ge 60) { Write-Output '  ...'; break }
    }
}
