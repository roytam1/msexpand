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

function Make-Psf([string]$tag, [string]$algId, [string]$outName) {
    $data = [System.IO.File]::ReadAllBytes("../xpress/$tag`_data.bin")
    $expect = [System.IO.File]::ReadAllBytes("../xpress/$tag`_expected.bin")
    $crc = Get-Crc32 $data

    $xmlTemplate = @"
<?xml version="1.0" encoding="UTF-8"?>
<Container name="xpress.psf" type="PSF" version="1" length="0">
  <Files>
    <File name="$outName" id="1" algId="$algId" length="$($expect.Length)" time="0" attr="32">
      <Hash alg="CRC32" value="$('{0:X8}' -f $crc)" length="4"/>
      <Delta><Source type="CIX_SOURCE_RAW" name="$outName" offset="000000" length="$($data.Length)"/></Delta>
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
    [System.IO.File]::WriteAllBytes("xpress_$tag.psf", $ms.ToArray())
    [System.IO.File]::WriteAllBytes("xpress_$tag`_expected.bin", $expect)
    Write-Output ("xpress_{0}.psf: algId={1} compressed={2} -> {3} bytes" -f $tag, $algId, $data.Length, $expect.Length)
}

Make-Psf '00' '3' 'plain_xpress.txt'
Make-Psf '39' '4' 'huff_xpress.txt'
