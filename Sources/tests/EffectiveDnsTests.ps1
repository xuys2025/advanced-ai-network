param([string]$Setup=(Join-Path $PSScriptRoot '..\..\Guard\Guard-Setup.ps1'))
$ErrorActionPreference='Stop'
$errors=$null;$tokens=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $Setup).Path,[ref]$tokens,[ref]$errors)
if($errors){throw $errors[0]}
$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-EffectiveCoverage'},$true)
. ([scriptblock]::Create($fn.Extent.Text))
$keywordMarker=$PSCommandPath
$dispatchDns='127.0.0.2'
$namespaces=@('Example.test','.example.test')
function Get-DnsClientNrptPolicy([switch]$Effective,$ErrorAction){
    if(!$Effective){throw 'Expected effective policy.'}
    $script:queries++;$fixture
}
function Row($names,$servers){[pscustomobject]@{Namespace=$names;NameServers=$servers}}
function Expect($covered){
    $script:queries=0
    $result=Get-EffectiveCoverage
    if($queries -ne 1 -or $result.required -ne 3 -or $result.covered -ne $covered){throw "Unexpected DNS coverage $($result.covered)/$($result.required), queries=$queries"}
}
$right=Row @('EXAMPLE.test','.EXAMPLE.test') $dispatchDns
$wildcard=Row '.' '127.0.0.3'
$bad=Row '.example.test' @($dispatchDns,'8.8.8.8')
$fixture=@($right,$wildcard);Expect 3
$fixture=@($bad,$right,$wildcard);Expect 2
$fixture=@($right,$wildcard,$bad);Expect 2
$fixture=@($right,$right,(Row '.' $dispatchDns));Expect 2
$fixture=@();Expect 0
Write-Output 'PASS one effective query, aliases, wildcard, missing, conflicting and extra resolvers.'
