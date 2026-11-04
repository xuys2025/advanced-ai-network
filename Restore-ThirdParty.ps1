Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$sourceRoot=Join-Path $PSScriptRoot 'Sources\third_party'
$manifest=Join-Path $sourceRoot 'encoded-sources.json'
if(!(Test-Path -LiteralPath $manifest)){throw 'Extract the third-party source download into this directory first.'}
$manifestEntries=Get-Content -LiteralPath $manifest -Raw -Encoding UTF8 | ConvertFrom-Json
foreach($entry in $manifestEntries){
    if($entry.name -notmatch '^[A-Za-z0-9._-]+$' -or $entry.sha256 -notmatch '^[a-f0-9]{64}$'){throw 'Invalid source manifest.'}
    $target=Join-Path $sourceRoot $entry.name
    $encoded=$target+'.b64'
    if((Test-Path -LiteralPath $target)-and(Get-FileHash -LiteralPath $target).Hash.ToLowerInvariant()-eq$entry.sha256){Write-Output ('Already verified: '+$entry.name);continue}
    if(Test-Path -LiteralPath $target){throw ('Existing file differs; move it aside before restoring: '+$entry.name)}
    $temporary=Join-Path $sourceRoot ([Guid]::NewGuid().ToString('N')+'.restore.tmp')
    $inputStream=$null;$outputStream=$null
    try{
        $inputStream=[IO.File]::OpenText($encoded)
        $outputStream=[IO.File]::Create($temporary)
        while($null -ne ($line=$inputStream.ReadLine())){if($line.Length){$bytes=[Convert]::FromBase64String($line);$outputStream.Write($bytes,0,$bytes.Length)}}
        $outputStream.Dispose();$outputStream=$null
        if((Get-FileHash -LiteralPath $temporary).Hash.ToLowerInvariant()-ne$entry.sha256){throw ('Source checksum mismatch: '+$entry.name)}
        Move-Item -LiteralPath $temporary -Destination $target
        Write-Output ('Restored and verified: '+$entry.name)
    }finally{
        if($outputStream){$outputStream.Dispose()};if($inputStream){$inputStream.Dispose()}
        if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary}
    }
}
