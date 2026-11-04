param([string]$Original,[string]$Output=(Join-Path $PSScriptRoot 'Clash-Merged.js'))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$previous=if($Original){[IO.File]::ReadAllText([IO.Path]::GetFullPath($Original),[Text.Encoding]::UTF8)}else{''}
if($previous.Contains('applyAdvancedAINetworkLan')){throw 'The source script already contains LAN rules; edit it directly instead of nesting another copy.'}
$rules=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Clash-Rules.js'),[Text.Encoding]::UTF8)
$merged="const previousMain=(function(){`n"+$previous+"`nreturn typeof main==='function'?main:null;`n})();`n"+$rules+"`nfunction main(config,profileName){if(previousMain)config=previousMain(config,profileName)||config;return applyAdvancedAINetworkLan(config);}`n"
if($Original -and [IO.Path]::GetFullPath($Original) -eq [IO.Path]::GetFullPath($Output)){throw 'Use a different output file; keep the original script for rollback.'}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($Output),$merged,[Text.UTF8Encoding]::new($false))
Write-Output ('Generated '+[IO.Path]::GetFullPath($Output)+'. Apply it manually in Clash; the running configuration was not changed.')
