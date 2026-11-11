# Exact owned usbipd rule only. No device, module, bind/attach or policy changes.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Apply','Rollback')][string]$Mode,
      [Parameter(Mandatory)][string]$RunDirectory)
$ErrorActionPreference='Stop'
$receiptFile=Join-Path $RunDirectory 'firewall-receipt.json'
$outFile=Join-Path $RunDirectory ('firewall-'+$Mode.ToLowerInvariant()+'-result.json')
if(Test-Path -LiteralPath $outFile){throw 'Action already recorded; no automatic retry'}
function Read-OwnedRule([string]$Name) {
    $rule=Get-NetFirewallRule -PolicyStore PersistentStore -Name $Name -ErrorAction Stop
    $app=$rule|Get-NetFirewallApplicationFilter
    $port=$rule|Get-NetFirewallPortFilter
    $address=$rule|Get-NetFirewallAddressFilter
    $interface=$rule|Get-NetFirewallInterfaceFilter
    return [ordered]@{Name=$rule.Name;DisplayName=$rule.DisplayName;Enabled=$rule.Enabled.ToString();Direction=$rule.Direction.ToString();Action=$rule.Action.ToString();Profile=$rule.Profile.ToString();Program=$app.Program;Protocol=$port.Protocol;LocalPort=$port.LocalPort;RemotePort=$port.RemotePort;LocalAddress=@($address.LocalAddress);RemoteAddress=@($address.RemoteAddress);InterfaceAlias=@($interface.InterfaceAlias);PolicyStoreSourceType=$rule.PolicyStoreSourceType.ToString()}
}
function Same-State($One,$Two) {
    foreach($name in @('Name','DisplayName','Enabled','Direction','Action','Profile','Program','Protocol','LocalPort','RemotePort','PolicyStoreSourceType')) {
        if([string]$One[$name] -cne [string]$Two.$name){return $false}
    }
    foreach($name in @('LocalAddress','RemoteAddress','InterfaceAlias')) {
        if((@($One[$name])|ConvertTo-Json -Compress) -cne (@($Two.$name)|ConvertTo-Json -Compress)){return $false}
    }
    return $true
}
$result=[ordered]@{mode=$Mode;state='PRECHECK';utc_started=[DateTime]::UtcNow.ToString('o');mutation_started=$false;error=$null}
try {
    $principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator token required for exact firewall scope update'}
    $request=Get-Content -LiteralPath (Join-Path $RunDirectory 'firewall-request.json') -Raw|ConvertFrom-Json
    $name=$request.owned_rule_name
    if($name -ne '{5D9A972C-A54A-4CC3-A65B-A38B12A16DC1}'){throw 'Unexpected rule identity'}
    $current=Read-OwnedRule $name
    if($Mode -eq 'Apply') {
        if(Test-Path -LiteralPath $receiptFile){throw 'Receipt exists; do not duplicate apply'}
        if(-not (Same-State $current $request.before)){throw 'Firewall rule changed since review'}
        $windows=@(Get-NetIPAddress -AddressFamily IPv4|Where-Object InterfaceAlias -eq $request.network.interface_alias)
        if($windows.Count -ne 1 -or $windows[0].IPAddress -ne $request.network.gateway -or $windows[0].PrefixLength -ne $request.network.prefixlen){throw 'Windows WSL interface changed'}
        $modeText=(& "$env:SystemRoot\System32\wsl.exe" -d Ubuntu --exec wslinfo --networking-mode|Out-String).Trim()
        if($LASTEXITCODE -ne 0 -or $modeText -ne 'nat'){throw 'WSL network mode changed'}
        $addressText=(& "$env:SystemRoot\System32\wsl.exe" -d Ubuntu --exec ip -j -4 address show eth0|Out-String)
        if($LASTEXITCODE -ne 0){throw 'WSL address query failed'}
        $addresses=@($addressText|ConvertFrom-Json)
        $guest=@($addresses[0].addr_info|Where-Object {$_.family -eq 'inet' -and $_.scope -eq 'global'})
        if($guest.Count -ne 1 -or $guest[0].local -ne $request.network.guest_ip){throw 'WSL guest IP changed'}
        $receipt=[ordered]@{state='APPLYING';owns_scope_change=$true;rule_name=$name;before=$current;proposed=$request.proposed;utc_started=[DateTime]::UtcNow.ToString('o')}
        $receipt|ConvertTo-Json -Depth 9|Set-Content -LiteralPath $receiptFile -Encoding utf8
        $params=@{PolicyStore='PersistentStore';Name=$name;LocalAddress=@($request.proposed.LocalAddress);RemoteAddress=@($request.proposed.RemoteAddress);InterfaceAlias=@($request.proposed.InterfaceAlias);ErrorAction='Stop'}
        $result.mutation_started=$true
        Set-NetFirewallRule @params
        $after=Read-OwnedRule $name
        $expected=$request.before
        $expected.LocalAddress=@($request.proposed.LocalAddress);$expected.RemoteAddress=@($request.proposed.RemoteAddress);$expected.InterfaceAlias=@($request.proposed.InterfaceAlias)
        if(-not (Same-State $after $expected)){throw 'Post-apply firewall verification failed; inspect receipt before retry'}
        $receipt.state='APPLIED';$receipt.after=$after;$receipt.utc_finished=[DateTime]::UtcNow.ToString('o')
        $receipt|ConvertTo-Json -Depth 9|Set-Content -LiteralPath $receiptFile -Encoding utf8
        $result.state='APPLIED';$result.after=$after
    } else {
        $receipt=Get-Content -LiteralPath $receiptFile -Raw|ConvertFrom-Json
        if($receipt.state -ne 'APPLIED' -or $receipt.owns_scope_change -ne $true -or $receipt.rule_name -ne $name){throw 'Matching applied ownership receipt required'}
        if(-not (Same-State $current $receipt.after)){throw 'Rule changed since our update; refuse overwriting concurrent changes'}
        $result.mutation_started=$true
        Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -LocalAddress @($receipt.before.LocalAddress) -RemoteAddress @($receipt.before.RemoteAddress) -InterfaceAlias @($receipt.before.InterfaceAlias) -ErrorAction Stop
        $after=Read-OwnedRule $name
        if(-not (Same-State $after $receipt.before)){throw 'Rollback verification failed'}
        $result.state='REVERTED';$result.after=$after
    }
} catch {
    $result.state='FAILED';$result.error=$_.Exception.Message
} finally {
    $result.utc_finished=[DateTime]::UtcNow.ToString('o')
    $result|ConvertTo-Json -Depth 9|Set-Content -LiteralPath $outFile -Encoding utf8
}
