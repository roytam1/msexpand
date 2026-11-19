$ErrorActionPreference = 'Stop'

function Decode-GoString([string]$s) {
    $bytes = New-Object System.Collections.Generic.List[byte]
    $i = 0
    while ($i -lt $s.Length) {
        $c = $s[$i]
        if ($c -eq '\') {
            $n = $s[$i + 1]
            if ($n -eq 'x') {
                $hex = $s.Substring($i + 2, 2)
                $bytes.Add([byte]([Convert]::ToInt32($hex, 16)))
                $i += 4
                continue
            }
            switch ($n) {
                'n' { $bytes.Add([byte]10) }
                'r' { $bytes.Add([byte]13) }
                't' { $bytes.Add([byte]9) }
                '\' { $bytes.Add([byte]92) }
                '"' { $bytes.Add([byte]34) }
                '0' { $bytes.Add([byte]0) }
                default { throw "unknown escape \\$n" }
            }
            $i += 2
            continue
        }
        $bytes.Add([byte][int]$c)
        $i++
    }
    return $bytes.ToArray()
}

$src = '\\roy-xp\c\devel\cabarc\go-ntfs\parser\xpress_test_data.go'
$outDir = 'xpress'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$rx = '^\s*\{"([^"]*)", \[\]byte\("(.*)"\), \[\]byte\("(.*)"\), (true|false)\}'
$n = 0
$manifest = New-Object System.Collections.Generic.List[string]
foreach ($line in (Get-Content $src)) {
    $m = [regex]::Match($line, $rx)
    if (-not $m.Success) { continue }
    $name = $m.Groups[1].Value
    $data = Decode-GoString $m.Groups[2].Value
    $expect = Decode-GoString $m.Groups[3].Value
    $huff = $m.Groups[4].Value -eq 'true'
    $tag = '{0:D2}' -f $n
    [System.IO.File]::WriteAllBytes((Join-Path $outDir "$tag`_data.bin"), $data)
    [System.IO.File]::WriteAllBytes((Join-Path $outDir "$tag`_expected.bin"), $expect)
    $manifest.Add("$tag|$huff|$($data.Length)|$($expect.Length)|$name")
    $n++
}
[System.IO.File]::WriteAllLines((Join-Path $outDir 'manifest.txt'), $manifest)
Write-Output "wrote $n vectors"
