Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($PSScriptRoot)+'\'
$checked=0
foreach($line in Get-Content (Join-Path $root 'SHA256SUMS.txt') -Encoding UTF8){if(!$line){continue};if($line-notmatch'^([0-9a-f]{64})  (.+)$'){throw 'Invalid checksum line.'};$expected=$Matches[1];$relative=$Matches[2];$file=[IO.Path]::GetFullPath((Join-Path $root $relative));if(!$file.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){throw 'Invalid manifest path.'};if(!(Test-Path -LiteralPath $file)-or(Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant()-ne$expected){throw ('Checksum mismatch: '+$relative)};$checked++}
Write-Output ('PASS '+$checked+' packaged file hashes. This checks integrity, not publisher identity.')
