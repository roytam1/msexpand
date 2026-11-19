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

$d1 = [System.Text.Encoding]::ASCII.GetBytes('Hello, world!')
$d2 = [System.Text.Encoding]::ASCII.GetBytes('Second file!')
$c1 = Get-Crc32 $d1
$c2 = Get-Crc32 $d2

$xmlTemplate = @"
<?xml version="1.0" encoding="UTF-8"?>
<Container name="sample.psf" type="PSF" version="1" length="0">
  <Files>
    <File name="hello.txt" id="1" length="$($d1.Length)" time="0" attr="32">
      <Hash alg="CRC32" value="$('{0:X8}' -f $c1)" length="4"/>
      <Delta><Source type="CIX_SOURCE_RAW" name="hello.txt" offset="000000" length="$($d1.Length)"/></Delta>
    </File>
    <File name="sub\second.txt" id="2" length="$($d2.Length)" time="0" attr="32">
      <Hash alg="CRC32" value="$('{0:X8}' -f $c2)" length="4"/>
      <Delta><Source type="CIX_SOURCE_RAW" name="second.txt" offset="000001" length="$($d2.Length)"/></Delta>
    </File>
  </Files>
</Container>
"@
$probe = [System.Text.Encoding]::UTF8.GetBytes($xmlTemplate)
$dataOff = 48 + $probe.Length
$off1 = '{0:D6}' -f $dataOff
$off2 = '{0:D6}' -f ($dataOff + $d1.Length)
$xml = $xmlTemplate.Replace('000000', $off1).Replace('000001', $off2)
$xb = [System.Text.Encoding]::UTF8.GetBytes($xml)
if ($xb.Length -ne $probe.Length) { throw 'XML length changed after substituting offsets' }

$header = New-Object byte[] 48
$magic = [System.Text.Encoding]::ASCII.GetBytes('PSTREAM')
[Array]::Copy($magic, 0, $header, 0, $magic.Length)
[Array]::Copy([BitConverter]::GetBytes([int]48), 0, $header, 40, 4)
[Array]::Copy([BitConverter]::GetBytes([int]$xb.Length), 0, $header, 44, 4)

$ms = New-Object System.IO.MemoryStream
$ms.Write($header, 0, 48)
$ms.Write($xb, 0, $xb.Length)
$ms.Write($d1, 0, $d1.Length)
$ms.Write($d2, 0, $d2.Length)
[System.IO.File]::WriteAllBytes('sample.psf', $ms.ToArray())
Write-Output ("crc1={0:X8} crc2={1:X8} psf={2} bytes dataOff={3} indexLen={4}" -f $c1, $c2, $ms.Length, $dataOff, $xb.Length)
