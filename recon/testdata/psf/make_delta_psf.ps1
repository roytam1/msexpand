$ErrorActionPreference = 'Stop'

function Get-Crc32([byte[]]$data) {
    $tbl = New-Object uint32[] 256
    for ($n = 0; $n -lt 256; $n++) {
        $c = [uint32]$n
        for ($k = 0; $k -lt 8; $k++) {
            if (($c -band 1) -ne 0) { $c = [uint32]([uint32]3988292384 -bxor ($c -shr 1)) }
            else { $c = [uint32]($c -shr 1) }
        }
        $tbl[$n] = $c
    }
    $crc = [uint32]4294967295
    foreach ($b in $data) {
        $crc = [uint32]($tbl[($crc -bxor $b) -band 0xFF] -bxor ($crc -shr 8))
    }
    return [uint32]($crc -bxor [uint32]4294967295)
}

$d = '..\delta'
$base = [System.IO.File]::ReadAllBytes("$d\d0_src.bin")
$delta = [System.IO.File]::ReadAllBytes("$d\d0.pa30")
$tgt = [System.IO.File]::ReadAllBytes("$d\d0_tgt.bin")
$crcBase = Get-Crc32 $base
$crcDelta = Get-Crc32 $delta

$xmlTemplate = @"
<?xml version="1.0" encoding="UTF-8"?>
<Container name="delta.psf" type="PSF" version="1" length="0">
  <Files>
    <File name="base.bin" id="1" length="$($base.Length)" time="0" attr="32">
      <Hash alg="CRC32" value="$('{0:X8}' -f $crcBase)" length="4"/>
      <Delta><Source type="CIX_SOURCE_RAW" name="base.bin" offset="000000" length="$($base.Length)"/></Delta>
    </File>
    <File name="result.bin" id="2" length="$($tgt.Length)" time="0" attr="32">
      <Hash alg="CRC32" value="$('{0:X8}' -f $crcDelta)" length="4"/>
      <Delta>
        <Basis file="1" length="$($base.Length)"/>
        <Source type="CIX_SOURCE_PA30" name="result.bin" offset="000001" length="$($delta.Length)"/>
      </Delta>
    </File>
  </Files>
</Container>
"@
$probe = [System.Text.Encoding]::UTF8.GetBytes($xmlTemplate)
$dataOff = 48 + $probe.Length
$off1 = '{0:D6}' -f $dataOff
$off2 = '{0:D6}' -f ($dataOff + $base.Length)
$xml = $xmlTemplate.Replace('000000', $off1).Replace('000001', $off2)
$xb = [System.Text.Encoding]::UTF8.GetBytes($xml)
if ($xb.Length -ne $probe.Length) { throw "XML length changed $($xb.Length) vs $($probe.Length)" }

$header = New-Object byte[] 48
$magic = [System.Text.Encoding]::ASCII.GetBytes('PSTREAM')
[Array]::Copy($magic, 0, $header, 0, $magic.Length)
[Array]::Copy([BitConverter]::GetBytes([int]48), 0, $header, 40, 4)
[Array]::Copy([BitConverter]::GetBytes([int]$xb.Length), 0, $header, 44, 4)

$ms = New-Object System.IO.MemoryStream
$ms.Write($header, 0, 48)
$ms.Write($xb, 0, $xb.Length)
$ms.Write($base, 0, $base.Length)
$ms.Write($delta, 0, $delta.Length)
[System.IO.File]::WriteAllBytes('delta.psf', $ms.ToArray())
[System.IO.File]::WriteAllBytes('delta_expected.bin', $tgt)
Write-Output ("delta.psf: base={0} delta={1} target={2}" -f $base.Length, $delta.Length, $tgt.Length)
