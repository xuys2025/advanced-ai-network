param([string]$Setup=(Join-Path $PSScriptRoot '..\..\Guard\Guard-Setup.ps1'))
$ErrorActionPreference='Stop'
$errors=$null;$tokens=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $Setup).Path,[ref]$tokens,[ref]$errors)
if($errors){throw $errors[0]}
$fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'TunFirewallChanges'},$true)
if(!$fn){throw 'Missing TUN firewall comparator.'}
. ([scriptblock]::Create($fn.Extent.Text))
$tunPrefix='198.19.64.0/18'
$rule=[pscustomobject]@{Direction='Outbound';Action='Block';Enabled='True';Profile='Any'}
$aliases=@('Ethernet','Wi-Fi')
foreach($form in $tunPrefix,'198.19.64.0/255.255.192.0','198.19.64.0-198.19.127.255'){
    $diff=TunFirewallChanges $rule @($form) @('WI-FI','ethernet') $aliases
    if($diff.Count){throw 'Equivalent TUN rule was rewritten.'}
}
$diff=TunFirewallChanges $rule @($tunPrefix) @('Ethernet') $aliases
if($diff.Count -ne 1 -or !$diff.ContainsKey('InterfaceAlias')){throw 'Interface change not isolated.'}
$diff=TunFirewallChanges $rule @($tunPrefix,'192.0.2.1') $aliases $aliases
if($diff.Count -ne 1 -or $diff.RemoteAddress -ne $tunPrefix){throw 'Address change not isolated.'}
foreach($name in 'Action','Direction','Profile','Enabled'){
    $saved=$rule.$name;$rule.$name='changed'
    $diff=TunFirewallChanges $rule @($tunPrefix) $aliases $aliases
    if($diff.Count -ne 1 -or $diff[$name] -ne $saved){throw ('Bad repair: '+$name)}
    $rule.$name=$saved
}
Write-Output 'PASS TUN firewall canonical addresses, interface set and single-field repairs.'
