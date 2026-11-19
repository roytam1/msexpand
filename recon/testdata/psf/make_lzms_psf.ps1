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

$data = [System.IO.File]::ReadAllBytes('../lzms/v1_comp.bin')
$expect = [System.IO.File]::ReadAllBytes('../lzms/v1_in.bin')
$crc = Get-Crc32 $data

$xmlTemplate = @"
<?xml version="1.0" encoding="UTF-8"?>
<Container name="lzms.psf" type="PSF" version="1" length="0">
  <Files>
    <File name="lzms_out.txt" id="1" algId="5" length="$($expect.Length)" time="0" attr="32">
      <Hash alg="CRC32" value="$('{0:X8}' -f $crc)" length="4"/>
      <Delta><Source type="CIX_SOURCE_RAW" name="lzms_out.txt" offset="000000" length="$($data.Length)"/></Delta>
    </File>
  </Files>
</Container>
"@
$probe = [System.Text.Encoding]::UTF8.GetBytes($xmlTemplate)
$dataOff = 48 + $probe.Length
$xml = $xmlTemplate.Replace('000000', ('{0:D6}' -f $dataOff))
$xb = [System.Text.Encoding]::UTF8.GetBytes($xml)
if ($xb.Length -ne $probe.Length) { throw 'XML length changed' }

$header = New-Object byte[] 48
$magic = [System.Text.Encoding]::ASCII.GetBytes('PSTREAM')
[Array]::Copy($magic, 0, $header, 0, $magic.Length)
[Array]::Copy([BitConverter]::GetBytes([int]48), 0, $header, 40, 4)
[Array]::Copy([BitConverter]::GetBytes([int]$xb.Length), 0, $header, 44, 4)

$ms = New-Object System.IO.MemoryStream
$ms.Write($header, 0, 48)
$ms.Write($xb, 0, $xb.Length)
$ms.Write($data, 0, $data.Length)
[System.IO.File]::WriteAllBytes('lzms.psf', $ms.ToArray())
[System.IO.File]::WriteAllBytes('lzms_expected.bin', $expect)
Write-Output ("lzms.psf: comp={0} -> {1} bytes" -f $data.Length, $expect.Length)
