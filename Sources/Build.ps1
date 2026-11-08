param([string]$Zig,[switch]$ManagedOnly)
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'compatibility\Runtime.ps1')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$compatibilityRoot=Join-Path (Split-Path -Parent $PSScriptRoot) 'compatibility'
$compatibility=Join-Path $compatibilityRoot 'Compatibility.cs'
$out=Join-Path $PSScriptRoot 'build';$null=New-Item -ItemType Directory -Path $out -Force
$csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(!(Test-Path -LiteralPath $csc)){throw 'Install .NET Framework 4.8 on Windows x64.'}
if(!$ManagedOnly){
    if(!$Zig){$command=Get-Command zig.exe -ErrorAction SilentlyContinue;if($command){$Zig=$command.Source}else{throw 'Pass -Zig with the path to Zig 0.15.1, or use -ManagedOnly to reuse the supplied native core.'}}
    $env:ZIG_GLOBAL_CACHE_DIR=Join-Path $out 'zig-global';$env:ZIG_LOCAL_CACHE_DIR=Join-Path $out 'zig-local'
    $src=Join-Path $PSScriptRoot 'third_party\ProxyBridge\src';$sdk=Join-Path $PSScriptRoot 'third_party\WinDivertSDK'
    $files=@(Get-ChildItem -LiteralPath $src -Filter *.c|Sort-Object Name|Select-Object -ExpandProperty FullName)
    & $Zig cc -target x86_64-windows-gnu -shared -O2 -g0 -DPROXYBRIDGE_EXPORTS -fms-extensions -Wno-unknown-pragmas -I (Join-Path $sdk 'include') -I $src -I $compatibilityRoot @files (Join-Path $sdk 'x64\WinDivert.lib') -lws2_32 -liphlpapi -ladvapi32 -lpsapi -o (Join-Path $out 'ProxyBridgeCore.dll')
    if($LASTEXITCODE -ne 0){throw 'Native core compilation failed.'}
}
$refs=@('/r:System.Web.Extensions.dll','/r:System.ServiceProcess.dll','/r:Microsoft.CSharp.dll')
$gateway=@(Get-ChildItem (Join-Path $PSScriptRoot 'gateway') -Filter *.cs|Select-Object -ExpandProperty FullName)
$gateway+=@(Get-ChildItem (Join-Path $PSScriptRoot 'native') -Filter *.cs|Select-Object -ExpandProperty FullName)
$gateway+= $compatibility
foreach($main in @('GatewayService','IdentityProbe','SetupInspect','DnsTests','GatewayValidationTests','IdentityPathTests','ProtectionAudit','RouteProbe','ManagedRulesTests','GuardPolicyTool')){
    & $csc /nologo /utf8output /optimize+ /debug- /platform:x64 /target:exe @refs ('/main:'+$main) ('/out:'+(Join-Path $out ($main+'.exe'))) @gateway
    if($LASTEXITCODE -ne 0){throw ('Compilation failed: '+$main)}
}
$snapshot=Join-Path $PSScriptRoot 'gateway\StatusSnapshotFile.cs'
& $csc /nologo /utf8output /optimize+ /debug- /platform:x64 /target:exe /r:System.Web.Extensions.dll ('/out:'+(Join-Path $out 'AdvancedAINetworkAgent.exe')) (Join-Path $PSScriptRoot 'gateway\GatewayAgent.cs') $snapshot $compatibility
if($LASTEXITCODE -ne 0){throw 'Agent compilation failed.'}
$guard=@(Get-ChildItem (Join-Path $PSScriptRoot 'guard') -Filter *.cs|Select-Object -ExpandProperty FullName)
$guard+=$compatibility
foreach($main in @('AdvancedAINetwork.GuardService','GuardAnswerTests','Regression','RelayRegression')){
    $name=if($main -eq 'AdvancedAINetwork.GuardService'){'AdvancedAINetworkGuard'}else{$main}
    $extra=@()
    if($main -in 'Regression','RelayRegression'){$extra+=Join-Path $PSScriptRoot ('tests\'+$main+'.cs')}
    & $csc /nologo /utf8output /optimize+ /debug- /platform:x64 /target:exe @refs /r:System.Security.dll ('/main:'+$main) ('/out:'+(Join-Path $out ($name+'.exe'))) @guard @extra
    if($LASTEXITCODE -ne 0){throw ('Compilation failed: '+$main)}
}
& $csc /nologo /utf8output /optimize+ /debug- /platform:x64 /target:winexe /r:System.Web.Extensions.dll /r:System.Security.dll /main:AdvancedAINetwork.DesktopLauncher ('/out:'+(Join-Path $out 'AdvancedAINetworkLauncher.exe')) (Join-Path $PSScriptRoot 'launcher\Lifecycle.cs') (Join-Path $PSScriptRoot 'guard\Data.cs') (Join-Path $PSScriptRoot 'guard\LogText.cs') $compatibility
if($LASTEXITCODE -ne 0){throw 'Launcher compilation failed.'}
foreach($name in @('WinDivert.dll','WinDivert64.sys')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot ('third_party\WinDivertSDK\x64\'+$name)) -Destination $out -Force}
$observer=@((Join-Path $PSScriptRoot 'observer\Protection.cs'),(Join-Path $PSScriptRoot 'observer\Sentinel.cs'),$snapshot,$compatibility)
foreach($main in 'Sentinel','AlertRegression'){
    $name=if($main -eq 'Sentinel'){'ProtectionObserver'}else{$main}
    $targetType=if($main -eq 'Sentinel'){'winexe'}else{'exe'}
    & $csc /nologo /optimize+ /platform:x64 ('/target:'+$targetType) ('/main:'+$main) ('/out:'+(Join-Path $out ($name+'.exe'))) @refs /r:System.Windows.Forms.dll /r:System.Drawing.dll @observer (Join-Path $PSScriptRoot 'tests\AlertRegression.cs')
    if($LASTEXITCODE){throw ('Observer compilation failed: '+$name)}
}
& $csc /nologo /optimize+ /platform:x64 /r:System.Web.Extensions.dll ('/out:'+(Join-Path $out 'NetworkProbe.exe')) (Join-Path $PSScriptRoot 'tests\NetworkProbe.cs')
if($LASTEXITCODE){throw 'Network probe compilation failed.'}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'tests\SlowFixture.ps1') -Destination $out -Force
foreach($test in @('DnsTests','GatewayValidationTests','IdentityPathTests','GuardAnswerTests','Regression','RelayRegression','AlertRegression')){& (Join-Path $out ($test+'.exe'));if($LASTEXITCODE -ne 0){throw ($test+' failed.')}}
$testOutput=Join-Path $out 'rule-test'
$null=New-Item -ItemType Directory -Path $testOutput -Force
$ruleFixture=Join-Path $out 'rule-source.yaml'
[IO.File]::WriteAllText($ruleFixture,(Get-AiCompatibility 'RuleFixture'),[Text.UTF8Encoding]::new($false))
& (Join-Path $out 'ManagedRulesTests.exe') $ruleFixture (Join-Path $PSScriptRoot 'tests\asn.json') $testOutput
if($LASTEXITCODE -ne 0){throw 'Managed rule tests failed.'}
Write-Output ('Built and tested: '+$out+'. No services or network settings changed.')
