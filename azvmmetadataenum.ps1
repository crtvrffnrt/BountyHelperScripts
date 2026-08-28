<#
.SYNOPSIS
    Azure IMDS metadata enumerator for Windows hosts.

.DESCRIPTION
    Windows/PowerShell implementation of azvmmetadataenum.sh. All IMDS calls
    are GET requests to 169.254.169.254, use Metadata:true, and bypass the
    machine proxy. Evidence files never contain access tokens.

.EXAMPLE
    .\azvmmetadataenum.ps1 -OutputDirectory .\imds-evidence
    .\azvmmetadataenum.ps1 -ClientId <user-assigned-identity-client-id>
#>
[CmdletBinding()]
param(
    [string]$ApiVersion,
    [ValidateRange(1, 300)][int]$TimeoutSeconds = 5,
    [ValidateRange(1, 300)][int]$EventTimeoutSeconds = 10,
    [string]$IdentityResource,
    [string]$ClientId,
    [string]$ObjectId,
    [string]$MsiResId,
    [switch]$SkipIdentity,
    [switch]$Raw,
    [string]$OutputDirectory,
    [switch]$NoColor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Imds = 'http://169.254.169.254'
$PreferredInstanceVersion = '2025-11-15'
$FallbackInstanceVersion = '2025-04-07'
$IdentityVersion = '2019-08-01'
$LoadBalancerVersion = '2020-10-01'
$EventsVersion = '2020-07-01'
$AttestedFallbackVersion = '2025-04-07'
$IdentityResources = @('https://management.azure.com/', 'https://graph.microsoft.com/', 'https://vault.azure.net', 'https://storage.azure.com/')
$RequestIndex = [System.Collections.Generic.List[object]]::new()
$UseColor = -not $NoColor -and -not [Console]::IsOutputRedirected

$selectors = @($ClientId, $ObjectId, $MsiResId | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($selectors.Count -gt 1) { throw 'Use only one of -ClientId, -ObjectId, or -MsiResId.' }
$IdentitySelector = if ($ClientId) { @{ client_id = $ClientId } } elseif ($ObjectId) { @{ object_id = $ObjectId } } elseif ($MsiResId) { @{ msi_res_id = $MsiResId } } else { @{} }

if ($OutputDirectory) {
    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
}

$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.UseProxy = $false
$client = [System.Net.Http.HttpClient]::new($handler)

function Write-Color([string]$Text, [ConsoleColor]$Color) {
    if ($UseColor) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
}
function Write-Section([string]$Name) {
    Write-Color ('-' * 60) Cyan
    Write-Color $Name White
    Write-Color ('-' * 60) Cyan
}
function Write-High([string]$Text) { Write-Color "[HIGH] $Text" Red }
function Write-Warn([string]$Text) { Write-Color "[WARN] $Text" Yellow }
function Write-Good([string]$Text) { Write-Color "[+] $Text" Green }
function Write-Info([string]$Text) { Write-Color "[*] $Text" Cyan }
function Write-Value([string]$Name, $Data) {
    if ($null -eq $Data -or [string]::IsNullOrWhiteSpace([string]$Data)) { $Data = '-' }
    Write-Host ('{0,-30} {1}' -f "${Name}:", $Data)
}
function ConvertFrom-JsonSafe([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return $Text | ConvertFrom-Json -ErrorAction Stop } catch { return $null }
}
function Get-Prop($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }; return $null
}
function Get-PathValue($Object, [string]$Path) {
    $value = $Object
    foreach ($part in $Path.Split('.')) { $value = Get-Prop $value $part; if ($null -eq $value) { return $null } }
    return $value
}
function Save-Evidence([string]$Name, [string]$Content) {
    if ($OutputDirectory -and -not [string]::IsNullOrEmpty($Content)) {
        [IO.File]::WriteAllText((Join-Path $OutputDirectory $Name), $Content, [Text.UTF8Encoding]::new($false))
    }
}
function Get-Sha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}
function ConvertFrom-Base64Url([string]$Value) {
    $s = $Value.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [Convert]::FromBase64String($s)
}
function Get-JwtClaims([string]$Token) {
    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) { return $null }
    try { return [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[1])) | ConvertFrom-Json } catch { return $null }
}
function Invoke-Imds([string]$Label, [string]$Path, [int]$RequestTimeout = $TimeoutSeconds, [hashtable]$ExtraHeaders = @{}) {
    $uri = "$Imds$Path"; $status = '000'; $body = ''; $errorText = ''
    $started = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $cts = [Threading.CancellationTokenSource]::new(); $cts.CancelAfter([TimeSpan]::FromSeconds($RequestTimeout))
    try {
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $uri)
        foreach ($key in $ExtraHeaders.Keys) { [void]$request.Headers.TryAddWithoutValidation($key, [string]$ExtraHeaders[$key]) }
        $response = $client.SendAsync($request, $cts.Token).GetAwaiter().GetResult()
        try { $status = [string][int]$response.StatusCode; $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult() } finally { $response.Dispose(); $request.Dispose() }
    } catch { $errorText = $_.Exception.Message }
    finally { $cts.Dispose() }
    $RequestIndex.Add([pscustomobject]@{ timestamp_utc=$started; label=$Label; http_status=$status; curl_status=if($status -eq '000'){'error'}else{'0'}; bytes=[Text.Encoding]::UTF8.GetByteCount($body); path=$Path })
    Start-Sleep -Milliseconds 220
    return [pscustomobject]@{ Status=$status; Body=$body; Error=$errorText }
}
function Invoke-Identity([string]$Resource) {
    $query = "api-version=$IdentityVersion&resource=$([Uri]::EscapeDataString($Resource))"
    foreach ($key in $IdentitySelector.Keys) { $query += "&$key=$([Uri]::EscapeDataString([string]$IdentitySelector[$key]))" }
    return Invoke-Imds "identity:$Resource" "/metadata/identity/oauth2/token?$query"
}
function Show-Field($Object, [string]$Label, [string]$Path) { Write-Value $Label (Get-PathValue $Object $Path) }
function Decode-MetadataBlob($Compute, [string]$Label, [string]$Property) {
    $encoded = Get-Prop $Compute $Property
    if ([string]::IsNullOrWhiteSpace($encoded)) { Write-Good "No $Label returned."; return }
    Write-High "$Label is present."
    try { $bytes = [Convert]::FromBase64String($encoded) } catch { Write-Warn "$Label is not valid Base64."; return }
    Write-Value "$Label decoded bytes" $bytes.Length; Write-Value "$Label SHA-256" (Get-Sha256 $bytes)
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if ($text -match '[^\x09\x0A\x0D\x20-\x7E]') { Write-Warn "$Label appears binary and was not printed."; return }
    Write-Host "Decoded $Label (first 200 lines):"
    $text -split "`r?`n" | Select-Object -First 200 | ForEach-Object { Write-Host "    $_" }
    if ($text -match '(?i)(pass(word)?|secret|token|api[_-]?key|client[_-]?secret|connectionstring|https?://)') { Write-High "$Label contains credential- or endpoint-related keywords; review carefully." }
}
function Get-LeafFields($Object, [string]$Prefix = '') {
    if ($null -eq $Object) { return @() }
    if ($Object -is [string] -or $Object -is [ValueType]) { return ,([pscustomobject]@{Path=$Prefix;Value=[string]$Object}) }
    $out = @()
    if ($Object -is [Collections.IEnumerable] -and -not ($Object -is [pscustomobject])) {
        $i=0; foreach ($item in $Object) { $out += Get-LeafFields $item "$Prefix[$i]"; $i++ }
    } else {
        foreach ($p in $Object.PSObject.Properties) { $next = if($Prefix){"$Prefix.$($p.Name)"}else{$p.Name}; $out += Get-LeafFields $p.Value $next }
    }
    return $out
}

try {
    Write-Host @'
    _                      ___ __  ______  ____
   / \   _____   _______  |_ _|  \/  |  \/  / ___
  / _ \ |_  / | | | '__|  | || |\/| | |\/| |/ _ \
 / ___ \ / /| |_| | |     | || |  | | |  | |  __/
/_/   \_/___|\__,_|_|    |___|_|  |_|_|  |_|\___|

        Azure IMDS Metadata Enumerator (PowerShell)
'@
    Write-Section '0. REACHABILITY AND VERSION NEGOTIATION'
    $versionsResponse = Invoke-Imds 'versions' '/metadata/versions' -ExtraHeaders @{Metadata='true'}
    $versions = ConvertFrom-JsonSafe $versionsResponse.Body
    if ($versionsResponse.Status -ne '200' -or -not $versions) { throw "IMDS versions endpoint unavailable (HTTP $($versionsResponse.Status); $($versionsResponse.Error))" }
    $advertised = @($versions.apiVersions | Sort-Object)[-1]
    $instanceVersion = if($ApiVersion){$ApiVersion}else{$PreferredInstanceVersion}
    Write-Value 'Newest advertised version' $advertised; Write-Value 'Preferred instance version' $instanceVersion
    Write-High 'IMDS is reachable without application authentication from this process.'
    Write-Host '    This is expected Azure behavior; it becomes security-relevant when untrusted code or SSRF can reach IMDS.'
    $instanceResponse = Invoke-Imds 'instance' "/metadata/instance?api-version=$instanceVersion" -ExtraHeaders @{Metadata='true'}
    $instance = ConvertFrom-JsonSafe $instanceResponse.Body
    if ($instanceResponse.Status -ne '200' -or -not $instance.compute -or -not $instance.network) {
        Write-Warn "Instance API $instanceVersion failed (HTTP $($instanceResponse.Status)); falling back."
        $instanceVersion = if($advertised){$advertised}else{$FallbackInstanceVersion}
        $instanceResponse = Invoke-Imds 'instance-fallback' "/metadata/instance?api-version=$instanceVersion" -ExtraHeaders @{Metadata='true'}; $instance = ConvertFrom-JsonSafe $instanceResponse.Body
    }
    if ($instanceResponse.Status -ne '200' -or -not $instance.compute -or -not $instance.network) { throw "Instance metadata unavailable (HTTP $($instanceResponse.Status); $($instanceResponse.Error))" }
    Write-Value 'Selected instance version' $instanceVersion
    if ($advertised -and $instanceVersion -ne $advertised) { Write-Info 'Selected version is accepted by this VM but differs from the versions endpoint.' }

    $compute=$instance.compute; $network=$instance.network
    Write-Section '1. AZURE RESOURCE AND IDENTITY CONTEXT'
    @(@('VM Name','name'),@('Computer Name','osProfile.computerName'),@('Admin Username','osProfile.adminUsername'),@('Provider','provider'),@('Resource Group','resourceGroupName'),@('Subscription ID','subscriptionId'),@('VM ID','vmId'),@('Region','location'),@('Azure Environment','azEnvironment'),@('Resource ID','resourceId')) | ForEach-Object { Show-Field $compute $_[0] $_[1] }
    Write-High 'The subscription, resource group, VM ID, and full ARM hierarchy are disclosed.'; Write-Info 'The admin username is useful for host and lateral-path review.'

    Write-Section '2. NETWORK AND LOAD-BALANCER CONTEXT'
    $nics=@($network.interface); Write-Value 'NIC Count' $nics.Count
    foreach($nic in $nics) { Write-Good "MAC=$(Get-Prop $nic 'macAddress') compartment=$(Get-Prop $nic 'interfaceCompartmentId')"; foreach($ip in @($nic.ipv4.ipAddress)){ Write-Value 'Private IPv4' $ip.privateIpAddress; Write-Value 'Public IPv4' $ip.publicIpAddress }; foreach($subnet in @($nic.ipv4.subnet)){ Write-High "Local Azure subnet: $($subnet.address)/$($subnet.prefix)" }; foreach($ip6 in @($nic.ipv6.ipAddress)){ Write-Value 'Private IPv6' $ip6.privateIpAddress } }
    $lbResponse=Invoke-Imds 'loadbalancer' "/metadata/loadbalancer?api-version=$instanceVersion" -ExtraHeaders @{Metadata='true'}; $lb=ConvertFrom-JsonSafe $lbResponse.Body
    if($lbResponse.Status -ne '200' -or -not $lb){ $lbResponse=Invoke-Imds 'loadbalancer-fallback' "/metadata/loadbalancer?api-version=$LoadBalancerVersion" -ExtraHeaders @{Metadata='true'}; $lb=ConvertFrom-JsonSafe $lbResponse.Body }
    if($lbResponse.Status -eq '200' -and $lb){ Write-Value 'Load-balancer API' $(if($lbResponse.label -eq 'loadbalancer-fallback'){$LoadBalancerVersion}else{$instanceVersion}); Write-Value 'Frontend mappings' @($lb.loadbalancer.publicIpAddresses).Count; Write-Value 'Inbound rules' @($lb.loadbalancer.inboundRules).Count; Write-Value 'Outbound rules' @($lb.loadbalancer.outboundRules).Count; foreach($p in @($lb.loadbalancer.publicIpAddresses)){ Write-High "Load balancer: frontend=$($p.frontendIpAddress) private=$($p.privateIpAddress)" } } else { Write-Warn "Load-balancer metadata unavailable (HTTP $($lbResponse.Status))." }

    Write-Section '3. SECURITY POSTURE'
    @(@('Security Type','securityProfile.securityType'),@('Secure Boot','securityProfile.secureBootEnabled'),@('Virtual TPM','securityProfile.virtualTpmEnabled'),@('Encryption at Host','securityProfile.encryptionAtHost'),@('SSH Password Disabled','osProfile.disablePasswordAuthentication'),@('Host Compatibility Layer','isHostCompatibilityLayerVm')) | ForEach-Object { Show-Field $compute $_[0] $_[1] }
    if($compute.securityProfile.secureBootEnabled -eq $false){Write-Warn 'Secure Boot is disabled.'}; if($compute.securityProfile.virtualTpmEnabled -eq $false){Write-Warn 'Virtual TPM is disabled.'}; if($compute.securityProfile.encryptionAtHost -eq $false){Write-Warn 'Encryption at host is disabled.'}; if($compute.osProfile.disablePasswordAuthentication -eq $false){Write-High 'Azure OS profile indicates SSH password authentication is enabled.'}

    Write-Section '4. OS, IMAGE, PLAN, AND CAPABILITIES'
    @(@('OS Type','osType'),@('Publisher','publisher'),@('Offer','offer'),@('SKU','sku'),@('Image Version','version'),@('VM Size','vmSize'),@('Image ID','storageProfile.imageReference.id'),@('Image Publisher','storageProfile.imageReference.publisher'),@('Image Offer','storageProfile.imageReference.offer'),@('Image SKU','storageProfile.imageReference.sku'),@('Image Requested Version','storageProfile.imageReference.version'),@('Image Exact Version','storageProfile.imageReference.exactVersion'),@('Community Gallery Image','storageProfile.imageReference.communityGalleryImageId'),@('Shared Gallery Image','storageProfile.imageReference.sharedGalleryImageId'),@('Plan Name','plan.name'),@('Plan Product','plan.product'),@('Plan Publisher','plan.publisher'),@('License Type','licenseType'),@('Hibernation Enabled','additionalCapabilities.hibernationEnabled')) | ForEach-Object { Show-Field $compute $_[0] $_[1] }

    Write-Section '5. SSH PUBLIC KEYS'
    $keys=@($compute.publicKeys); Write-Value 'Configured public keys' $keys.Count
    foreach($key in $keys){ Write-Value 'Authorized Keys Path' $key.path; $parts=$key.keyData -split ' ',3; Write-Value 'Key Type' $parts[0]; Write-Value 'Key Comment' $(if($parts.Count -gt 2){$parts[2]}else{'-'}) }

    Write-Section '6. TAGS AND ENVIRONMENT DISCLOSURE'
    $tags=@($compute.tagsList); Write-Value 'Structured tags' $tags.Count
    if($tags.Count){$tags | ForEach-Object {Write-Host "    $($_.name) = $($_.value)"}} elseif($compute.tags){$compute.tags -split ';' | ForEach-Object {Write-Host "    $_"}} else {Write-Good 'No tags were returned.'}; Write-Info 'Review tags for environment names, owners, applications, backup IDs, and internal references.'

    Write-Section '7. USER DATA AND CUSTOM DATA'; Decode-MetadataBlob $compute 'userData' 'userData'; Decode-MetadataBlob $compute 'customData' 'customData'

    Write-Section '8. STORAGE AND KEY-VAULT REFERENCES'
    $osDisk=$compute.storageProfile.osDisk
    @(@('OS Disk Name','name'),@('OS Disk OS type','osType'),@('OS Disk Size GB','diskSizeGB'),@('OS Disk Create option','createOption'),@('OS Disk Caching','caching'),@('OS Disk Storage type','managedDisk.storageAccountType'),@('OS Disk Managed disk ID','managedDisk.id'),@('OS Disk Ephemeral option','diffDiskSettings.option'),@('OS Disk Ephemeral placement','diffDiskSettings.placement'),@('OS Disk Full caching','diffDiskSettings.enableFullCaching'),@('OS Disk Write accelerator','writeAcceleratorEnabled')) | ForEach-Object { Show-Field $osDisk $_[0] $_[1] }
    @('encryptionSettings.diskEncryptionKey.sourceVault.id','encryptionSettings.diskEncryptionKey.secretUrl','encryptionSettings.keyEncryptionKey.sourceVault.id','encryptionSettings.keyEncryptionKey.keyUrl') | ForEach-Object { $ref=Get-PathValue $osDisk $_; if($ref){Write-High "Encryption/Key Vault reference: $ref"} }
    Write-Value 'Resource disk size' (Get-PathValue $compute 'storageProfile.resourceDisk.size'); $dataDisks=@($compute.storageProfile.dataDisks); Write-Value 'Data disk count' $dataDisks.Count; foreach($disk in $dataDisks){Write-Info "LUN=$($disk.lun) name=$($disk.name) size=$($disk.diskSizeGB)GB type=$($disk.managedDisk.storageAccountType) caching=$($disk.caching) ID=$($disk.managedDisk.id)"}

    Write-Section '9. TOPOLOGY AND PLACEMENT'
    @(@('VM Scale Set','vmScaleSetName'),@('VMSS Resource ID','virtualMachineScaleSet.id'),@('Placement Group','placementGroupId'),@('Host ID','host.id'),@('Host Group','hostGroup.id'),@('Interconnect Group','interconnectGroupId'),@('Interconnect Subgroup','interconnectSubgroupId'),@('Zone','zone'),@('Physical Zone','physicalZone'),@('Fault Domain','platformFaultDomain'),@('Sub-Fault Domain','platformSubFaultDomain'),@('System Fault Domain','systemFaultDomain'),@('Update Domain','platformUpdateDomain'),@('Priority','priority'),@('Eviction Policy','evictionPolicy'),@('In Standby Pool','isVmInStandbyPool'),@('Extended Location Name','extendedLocation.name'),@('Extended Location Type','extendedLocation.type')) | ForEach-Object { Show-Field $compute $_[0] $_[1] }
    if([string]$compute.priority -match '(?i)spot'){Write-High 'This appears to be a Spot VM.'}

    Write-Section '10. ATTESTED METADATA'
    $attestedResponse=Invoke-Imds 'attested' "/metadata/attested/document?api-version=$instanceVersion" -ExtraHeaders @{Metadata='true'}; $attested=ConvertFrom-JsonSafe $attestedResponse.Body; $attestedVersion=$instanceVersion
    if($attestedResponse.Status -ne '200' -or -not $attested.signature){$attestedVersion=$AttestedFallbackVersion; $attestedResponse=Invoke-Imds 'attested-fallback' "/metadata/attested/document?api-version=$attestedVersion" -ExtraHeaders @{Metadata='true'}; $attested=ConvertFrom-JsonSafe $attestedResponse.Body}
    if($attestedResponse.Status -eq '200' -and $attested.signature){ Write-Value 'Attested API' $attestedVersion; Write-Value 'Encoding' $attested.encoding; Write-Value 'Signature base64 bytes' $attested.signature.Length; try { $der=[Convert]::FromBase64String($attested.signature); Write-Value 'PKCS#7 SHA-256' (Get-Sha256 $der); Add-Type -AssemblyName System.Security; $cms=[Security.Cryptography.Pkcs.SignedCms]::new(); $cms.Decode($der); $cms.CheckSignature($true); $content=[Text.Encoding]::UTF8.GetString($cms.ContentInfo.Content); Write-Good 'PKCS#7 signature integrity verified (certificate chain trust not validated).'; $content | ConvertFrom-Json | ConvertTo-Json -Depth 20; Save-Evidence 'attested-content.json' $content } catch { Write-Warn "Could not extract/verify the PKCS#7 attested document: $($_.Exception.Message)" } } else { Write-Warn "Attested metadata unavailable (HTTP $($attestedResponse.Status))." }

    Write-Section '11. SCHEDULED EVENTS'
    $eventsResponse=Invoke-Imds 'scheduledevents' "/metadata/scheduledevents?api-version=$EventsVersion" $EventTimeoutSeconds @{Metadata='true'}; $events=ConvertFrom-JsonSafe $eventsResponse.Body
    if($eventsResponse.Status -eq '200' -and $events){$eventList=@($events.Events); Write-Value 'Scheduled events' $eventList.Count; if($eventList.Count){Write-High 'Azure infrastructure events are pending.'; $eventList | ConvertTo-Json -Depth 20}} elseif($eventsResponse.Status -eq '000'){Write-Warn "Scheduled-events request failed or timed out after ${EventTimeoutSeconds}s; state remains unknown."} else {Write-Warn "Scheduled-events metadata unavailable (HTTP $($eventsResponse.Status))."}

    Write-Section '12. MANAGED IDENTITY'
    if(-not $SkipIdentity){ if($IdentityResource){$IdentityResources += $IdentityResource}; foreach($resource in $IdentityResources){ Write-Warn "Requesting a managed-identity token for $resource."; $identityResponse=Invoke-Identity $resource; $identity=ConvertFrom-JsonSafe $identityResponse.Body; if($identityResponse.Status -eq '200' -and $identity.access_token){ $token=[string]$identity.access_token; Write-High "A managed identity token was issued for $resource."; [pscustomobject]@{token_type=$identity.token_type;resource=$identity.resource;expires_on=$identity.expires_on;not_before=$identity.not_before;client_id=$identity.client_id;object_id=$identity.object_id;msi_res_id=$identity.msi_res_id}|ConvertTo-Json; Write-Color "[SENSITIVE TOKEN: $resource] $token" Red; Write-Value 'Token SHA-256' (Get-Sha256 ([Text.Encoding]::UTF8.GetBytes($token))); $claims=Get-JwtClaims $token; if($claims){Write-Host 'JWT claims:'; [pscustomobject]@{aud=$claims.aud;iss=$claims.iss;tid=$claims.tid;oid=$claims.oid;appid=$claims.appid;azp=$claims.azp;idtyp=$claims.idtyp;xms_mirid=$claims.xms_mirid;roles=$claims.roles;scp=$claims.scp;nbf=$claims.nbf;exp=$claims.exp}|ConvertTo-Json; Save-Evidence ("identity-" + (($resource -replace '^https?://','') -replace '[^A-Za-z0-9._-]','-') + '-token-claims.json') ($claims|ConvertTo-Json -Depth 20)}; $redacted=$identity|Select-Object *; $redacted.access_token='[REDACTED]'; Save-Evidence ("identity-" + (($resource -replace '^https?://','') -replace '[^A-Za-z0-9._-]','-') + '-redacted.json') ($redacted|ConvertTo-Json -Depth 20) } else { Write-Value "Identity HTTP status ($resource)" $identityResponse.Status; if($identity){$identity|ConvertTo-Json -Depth 20}else{Write-Warn "Identity endpoint did not return JSON ($($identityResponse.Error))."}; Write-Info 'Identity not found may mean no identity is assigned, or the selected identity is invalid.' } }} else {Write-Info 'Managed-identity request skipped by operator.'}

    Write-Section '13. IMDS REQUEST-GUARD CHECKS'
    $noHeader=Invoke-Imds 'guard-no-metadata-header' "/metadata/instance?api-version=$instanceVersion"; $xff=Invoke-Imds 'guard-x-forwarded-for' "/metadata/instance?api-version=$instanceVersion" -ExtraHeaders @{Metadata='true';'X-Forwarded-For'='127.0.0.1'}
    Write-Value 'Without Metadata:true' "HTTP $($noHeader.Status)"; Write-Value 'With X-Forwarded-For' "HTTP $($xff.Status)"; if($noHeader.Status -ne '200'){Write-Good 'Metadata header requirement is enforced.'}else{Write-High 'Instance metadata was returned without the Metadata:true header.'}; if($xff.Status -ne '200'){Write-Good 'X-Forwarded-For requests are rejected.'}else{Write-High 'Instance metadata was returned despite X-Forwarded-For.'}

    Write-Section '14. COMPLETE FIELD INVENTORY'
    $computeFields=Get-LeafFields $compute 'compute'; $networkFields=Get-LeafFields $network 'network'; Write-Value 'Compute leaf fields' $computeFields.Count; Write-Value 'Network leaf fields' $networkFields.Count; @($computeFields+$networkFields)|Sort-Object Path|ForEach-Object{Write-Host ('    {0,-72} {1}' -f $_.Path,$_.Value)}
    if($Raw){Write-Section '15. RAW IMDS RESPONSES'; Write-Host 'Instance metadata:'; $instanceResponse.Body; if($lbResponse.Body){Write-Host 'Load-balancer metadata:';$lbResponse.Body}; if($eventsResponse.Body){Write-Host 'Scheduled-events metadata:';$eventsResponse.Body}; Write-Host 'Versions:';$versionsResponse.Body}
    Save-Evidence 'versions.json' $versionsResponse.Body; Save-Evidence 'instance.json' $instanceResponse.Body; Save-Evidence 'loadbalancer.json' $lbResponse.Body; Save-Evidence 'scheduledevents.json' $eventsResponse.Body; Save-Evidence 'attested.json' $attestedResponse.Body
    Write-Section 'EVIDENCE INDEX AND PRIORITIES'; $RequestIndex | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
    if($OutputDirectory){$RequestIndex|Export-Csv -NoTypeInformation -Delimiter "`t" -Path (Join-Path $OutputDirectory 'request-index.tsv'); Write-Good "Evidence saved under $OutputDirectory"}
    Write-Host "`nPrioritized next tests:"; @('Review decoded user/custom data and tags for secrets and internal endpoints.','Map disclosed private addresses/subnets only where they are in assessment scope.','If identity exists, enumerate Azure RBAC with the redacted identity context.','Review Key Vault/disk-key references and load-balancer mappings.','Compare Secure Boot, vTPM, encryption-at-host, and SSH posture to policy.','Treat IMDS reachability as impactful only when paired with untrusted local code or SSRF.') | ForEach-Object -Begin {$i=1} -Process {Write-Host "  $i. $_"; $i++}
    Write-Good 'IMDS metadata enumeration complete.'
} finally { $client.Dispose(); $handler.Dispose() }
