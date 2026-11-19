$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$project=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
function Read-Function([string]$File,[string]$Name){
    $tokens=$null;$errors=$null
    $tree=[Management.Automation.Language.Parser]::ParseFile((Join-Path $project $File),[ref]$tokens,[ref]$errors)
    if($errors){throw $errors[0]}
    $fn=$tree.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name},$true)
    [scriptblock]::Create($fn.Extent.Text)
}
. (Read-Function 'Install.ps1' 'Set-LauncherStartup')
. (Read-Function 'Install.ps1' 'Restore-GatewayFiles')
. (Read-Function 'Check.ps1' 'ConvertTo-ExitIPv4')
. (Read-Function 'Check.ps1' 'Test-ExitPaths')
. (Read-Function 'Guard\Guard-Setup.ps1' 'RepairRules')

if($env:GITHUB_ACTIONS -eq 'true'){
    $key='HKCU:\Software\AdvancedAINetwork-Test-'+[Guid]::NewGuid().ToString('N')
    try{
        Set-LauncherStartup $key 'first.exe'
        New-ItemProperty -LiteralPath $key -Name Fixture -PropertyType DWord -Value 123 | Out-Null
        Set-LauncherStartup $key 'second.exe'
        $value=Get-ItemProperty -LiteralPath $key
        if($value.Fixture -ne 123 -or $value.AdvancedAIPrivateNetwork -ne '"second.exe" --startup'){throw 'Login entry overwritten.'}
    }finally{if(Test-Path -LiteralPath $key){Remove-Item -LiteralPath $key}}
}

if((ConvertTo-ExitIPv4 '192.0.2.1') -ne '192.0.2.1'){throw 'Valid exit rejected.'}
foreach($invalid in @('','127.1','::1','<html>','192.0.2.400')){
    $accepted=$false
    try{$null=ConvertTo-ExitIPv4 $invalid;$accepted=$true}catch{}
    if($accepted){throw "Invalid exit accepted: $invalid"}
}
function Read-ExitIPv4([int]$Port){$script:ports+=$Port;return $samples.Dequeue()}
$result=@{};$ports=@()
$samples=[Collections.Queue]::new(@('192.0.2.1','192.0.2.2','192.0.2.2','192.0.2.2','192.0.2.2','192.0.2.2'))
Test-ExitPaths $true 7897
if(($ports -join ',') -ne '17891,0,7897,17891,0,7897'){throw 'Missing comparison on exit renewal.'}
$samples=[Collections.Queue]::new(@('192.0.2.1','192.0.2.2','192.0.2.1','192.0.2.2'))
$accepted=$false
try{Test-ExitPaths $false 0;$accepted=$true}catch{if($_.Exception.Message -notlike '*differ*'){throw}}
if($accepted){throw 'Wrong exit passed.'}

$guardPath=Join-Path ([IO.Path]::GetTempPath()) ('guard-setup-test-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $guardPath
$keywordMarker=Join-Path $guardPath 'keyword'
$managed=Join-Path $guardPath 'managed'
$namespaces=@('protected.example')
$comment='fixture'
$rules=@();$reject=$true
function AssertNoConflicts($allRules){}
function Get-DnsClientNrptRule($ErrorAction){$script:rules}
function Add-DnsClientNrptRule($Namespace,$NameServers,$Comment,$DisplayName,[switch]$PassThru){
    $r=[pscustomobject]@{Namespace=@($Namespace);NameServers=@($NameServers);Name=$Namespace;Comment=$Comment}
    $script:rules+=@($r)
    if($PassThru){$r}
}
function Set-DnsClientNrptRule($Name,$NameServers){($rules | Where-Object Name -eq $Name).NameServers=@($NameServers)}
function Remove-DnsClientNrptRule($Name,[switch]$Force){$script:rules=@($rules | Where-Object Name -ne $Name)}
function Clear-DnsClientCache{}
function Get-EffectiveCoverage([switch]$IncludeWildcard){@{covered=[int](!$reject);required=1}}
try{
    $backup=Join-Path $guardPath 'backup'
    $null=New-Item -ItemType Directory $backup
    $files=@('config.json','intent.json','TailscaleExit.exe')
    [IO.File]::WriteAllText((Join-Path $backup $files[0]),'old config')
    [IO.File]::WriteAllText((Join-Path $backup $files[1]),'paused')
    [IO.File]::WriteAllText((Join-Path $guardPath $files[0]),'new config')
    [IO.File]::WriteAllText((Join-Path $guardPath $files[2]),'new component')
    Restore-GatewayFiles $files $backup $guardPath
    Restore-GatewayFiles $files $backup $guardPath
    if([IO.File]::ReadAllText((Join-Path $guardPath $files[0])) -ne 'old config' -or [IO.File]::ReadAllText((Join-Path $guardPath $files[1])) -ne 'paused' -or (Test-Path (Join-Path $guardPath $files[2]))){throw 'Incomplete upgrade rollback.'}
    [IO.File]::WriteAllText($managed,'fixture')
    RepairRules
    if($rules.Name -contains '.'){throw 'Wildcard installed during bootstrap.'}
    try{RepairRules -ActivateKeywords;throw 'Expected incomplete coverage failure.'}catch{if($_.Exception.Message -notlike '*DNS*'){throw}}
    if($rules.Name -contains '.' -or (Test-Path $keywordMarker)){throw 'Failed activation retained wildcard.'}
    $reject=$false
    RepairRules -ActivateKeywords
    RepairRules
    if(@($rules|Where-Object Name -eq '.').Count -ne 1 -or !(Test-Path $keywordMarker)){throw 'Wildcard commit failed.'}
}finally{
    foreach($file in $files){foreach($folder in @($guardPath,$backup)){[IO.File]::Delete((Join-Path $folder $file))}}
    [IO.Directory]::Delete($backup)
    foreach($file in @($keywordMarker,$managed,(Join-Path $guardPath 'policy.lock'))){if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file}}
    [IO.Directory]::Delete($guardPath)
}
Write-Output 'PASS partial upgrade rollback, staged DNS activation, wildcard rollback, repeated repair, IPv4 validation and egress comparison.'
