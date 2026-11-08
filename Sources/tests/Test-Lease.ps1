# Run on an isolated Windows x64 test machine as its administrator.
$ErrorActionPreference='Stop'
$sources=Split-Path -Parent $PSScriptRoot
$out=Join-Path $sources 'build'
$fixture=Join-Path $out 'LeaseFixture.exe'
$probe=Join-Path $out 'ai-outage-fixture.exe'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /optimize+ /platform:x64 /define:GATE_FIXTURE /r:System.Web.Extensions.dll ('/out:'+$fixture) (Join-Path $PSScriptRoot 'LeaseFixture.cs') (Join-Path $sources 'gateway\GatewayFailClosed.cs') (Join-Path $sources 'gateway\ManagedRules.cs') (Join-Path (Split-Path -Parent $sources) 'compatibility\Compatibility.cs')
if($LASTEXITCODE){throw 'Could not build WFP lifetime fixture.'}
Copy-Item (Join-Path $out 'NetworkProbe.exe') $probe -Force
$listener=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
$start=[Diagnostics.ProcessStartInfo]::new($fixture)
$start.UseShellExecute=$false
$start.RedirectStandardInput=$true
$start.RedirectStandardOutput=$true
$process=$null
try{
    $listener.Start()
    $port=([Net.IPEndPoint]$listener.LocalEndpoint).Port
    $process=[Diagnostics.Process]::Start($start)
    $ready=$process.StandardOutput.ReadLineAsync()
    if(!$ready.Wait(20000) -or $ready.Result -ne 'ready'){throw 'WFP fixture did not start.'}
    $live=& $probe tcp 127.0.0.1 $port | ConvertFrom-Json
    if(!$live.ok){throw 'Test application could not connect while the gateway held a permit.'}
    $process.StandardInput.WriteLine('crash')
    if(!$process.WaitForExit(10000)){throw 'The test gateway did not exit.'}
    $denied=& $probe tcp 127.0.0.1 $port | ConvertFrom-Json
    if($denied.ok -or $denied.code -ne 10013){throw 'Windows did not deny the protected socket after gateway termination.'}
    $ordinary=& (Join-Path $out 'NetworkProbe.exe') tcp 127.0.0.1 $port | ConvertFrom-Json
    if(!$ordinary.ok){throw 'The unrelated application lost connectivity.'}
    Write-Output 'PASS persistent WFP blocks survived abrupt process exit, protected socket denied with 10013, unrelated socket connected.'
}finally{
    if($null -ne $process){if(!$process.HasExited){$process.Kill();$process.WaitForExit()};$process.Dispose()}
    $listener.Stop()
    & $fixture remove-fixture
    if($LASTEXITCODE){throw 'Fixture cleanup failed.'}
}
