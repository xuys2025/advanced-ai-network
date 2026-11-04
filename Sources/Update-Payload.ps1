param([string]$PackageRoot=(Split-Path -Parent $PSScriptRoot))
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PackageRoot=[IO.Path]::GetFullPath($PackageRoot)
if(!(Test-Path -LiteralPath (Join-Path $PackageRoot 'Install.ps1'))){throw 'Choose an extracted package, not a live installation.'}
$out=Join-Path $PSScriptRoot 'build'
foreach($name in @('GatewayService.exe','ProxyBridgeCore.dll','WinDivert.dll','WinDivert64.sys')){if(Test-Path -LiteralPath (Join-Path $out $name)){Copy-Item -LiteralPath (Join-Path $out $name) -Destination (Join-Path $PackageRoot 'Gateway') -Force}}
foreach($name in @('SetupInspect.exe','IdentityProbe.exe','ProtectionAudit.exe','RouteProbe.exe','DnsTests.exe','GatewayValidationTests.exe','GuardAnswerTests.exe')){Copy-Item -LiteralPath (Join-Path $out $name) -Destination (Join-Path $PackageRoot 'Tools') -Force}
Copy-Item -LiteralPath (Join-Path $out 'AdvancedAINetworkGuard.exe') -Destination (Join-Path $PackageRoot 'Guard') -Force
Copy-Item -LiteralPath (Join-Path $out 'AdvancedAINetworkAgent.exe') -Destination (Join-Path $PackageRoot 'App\resources\native') -Force
Copy-Item -LiteralPath (Join-Path $out 'AdvancedAINetworkLauncher.exe') -Destination (Join-Path $PackageRoot 'App') -Force
foreach($file in Get-ChildItem (Join-Path $PSScriptRoot 'client') -File){Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $PackageRoot 'App\resources\app') -Force}
Write-Output 'Payload refreshed. Run Install.ps1 to apply it; the running service was not modified.'
