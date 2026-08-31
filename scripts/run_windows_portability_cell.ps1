[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('3.11', '3.12', '3.13', '3.14')]
    [string]$PythonMinor = '3.11',

    [Parameter()]
    [string]$PythonExecutable = 'python',

    [Parameter()]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$validator = Join-Path $PSScriptRoot 'validate_windows_portability_cell.py'
$freezeScript = Join-Path $PSScriptRoot 'freeze_source_snapshot.py'
$boundedRunner = Join-Path $PSScriptRoot 'bounded_subprocess.py'
$networkProbe = Join-Path $PSScriptRoot 'portability_network_control.py'
$pythonCommand = @(Get-Command -Name $PythonExecutable -CommandType Application -ErrorAction Stop)[0]
$pythonPath = [IO.Path]::GetFullPath($pythonCommand.Source)
if (-not [IO.File]::Exists($pythonPath)) {
    throw 'resolved Python executable is not a regular existing file'
}
$nonce = [Guid]::NewGuid().ToString('N')
$cell = "windows-py$PythonMinor"
$utf8NoBom = [Text.UTF8Encoding]::new($false)
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$workRoot = [IO.Path]::Combine($tempRoot, "finplanbr-portability-windows-$nonce")
$ruleNames = [Collections.Generic.List[string]]::new()
$firewallSnapshot = [Collections.Generic.List[object]]::new()
$aclBackups = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::OrdinalIgnoreCase)
$aclRestored = $true
$firewallRulesAbsent = $true
$workCreated = $false

function Write-Utf8NoBom {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Text)
    [IO.File]::WriteAllText($Path, $Text, $script:utf8NoBom)
}

function Assert-OutsideRepository {
    param([Parameter(Mandatory)][string]$Path)
    $absolute = [IO.Path]::GetFullPath($Path)
    $prefix = $script:repositoryRoot.TrimEnd('\') + '\'
    if ($absolute.Equals($script:repositoryRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $absolute.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'portability output/work path must remain outside the checkout'
    }
    return $absolute
}

function Assert-UnderWorkRoot {
    param([Parameter(Mandatory)][string]$Path)
    $absolute = [IO.Path]::GetFullPath($Path)
    $prefix = $script:workRoot.TrimEnd('\') + '\'
    if (-not $absolute.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'candidate ACL target escaped the validated work root'
    }
    return $absolute
}

    function Invoke-PythonJson {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$Executable = $script:pythonPath,
        [switch]$AllowFailure,
        [int]$TimeoutSeconds = 300
    )
    $lines = & $script:pythonPath -I -S -B $script:boundedRunner `
        --json-envelope --timeout-seconds $TimeoutSeconds `
        --stdout-limit 33554432 --stderr-limit 33554432 `
        -- $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw 'bounded Python phase runner failed before emitting its envelope'
    }
    $envelope = (($lines -join "`n") | ConvertFrom-Json)
    if ($envelope.format -ne 'finplanbr.bounded-subprocess-envelope.v1') {
        throw 'bounded Python phase returned an invalid envelope'
    }
    if ($envelope.status -ne 'completed') {
        throw "bounded Python phase failed closed: $($envelope.failure_class)"
    }
    $returnCode = [int]$envelope.returncode
    $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([string]$envelope.stdout_base64))
    if ($returnCode -ne 0 -and -not $AllowFailure) {
        throw "Python phase failed with RC $returnCode; stderr_sha256=$($envelope.stderr_sha256)"
    }
    return [pscustomobject]@{ ReturnCode = $returnCode; Text = $text }
}

function Emit-Report {
    param([Parameter(Mandatory)][hashtable]$Report, [int]$ReturnCode)
    $text = $Report | ConvertTo-Json -Compress -Depth 20
    if ($script:OutputPath) {
        $target = Assert-OutsideRepository -Path $script:OutputPath
        $parent = Split-Path -Parent $target
        if ($parent) {
            [IO.Directory]::CreateDirectory($parent) | Out-Null
        }
        Write-Utf8NoBom -Path $target -Text ($text + "`n")
    }
    [Console]::Out.WriteLine($text)
    exit $ReturnCode
}

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
$isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
    Emit-Report -ReturnCode 1 -Report @{
        format = 'finplanbr.installed-portability-host-launch.v1'
        status = 'not_observed'
        cell = $cell
        reason = 'windows_firewall_control_requires_elevated_runner'
        audit_hook_fallback = $false
        authority = 'none'
        release_authorized = $false
    }
}

$phaseError = $null
$exercisePath = $null
$cleanupPath = $null
try {
    $workRoot = Assert-OutsideRepository -Path $workRoot
    [IO.Directory]::CreateDirectory($workRoot) | Out-Null
    $workCreated = $true
    $freezePath = Join-Path $workRoot 'source-freeze.json'
    $statePath = Join-Path $workRoot 'state.json'
    $boundaryPath = Join-Path $workRoot 'boundary.json'
    $exercisePath = Join-Path $workRoot 'exercise.json'
    $cleanupPath = Join-Path $workRoot 'cleanup.json'

    $freeze = Invoke-PythonJson -Arguments @('-I', '-B', $freezeScript)
    Write-Utf8NoBom -Path $freezePath -Text ($freeze.Text + "`n")
    $precontrol = Invoke-PythonJson -Arguments @(
        $networkProbe, '--expect', 'reachable', '--nonce', $nonce
    )
    $precontrolReport = $precontrol.Text | ConvertFrom-Json
    if ($precontrolReport.status -ne 'passed' -or -not $precontrolReport.connected) {
        throw 'Windows network precontrol did not connect before firewall activation'
    }

    $directVenv = Join-Path $workRoot 'venv-direct'
    $rebuiltVenv = Join-Path $workRoot 'venv-sdist-wheel'
    $programs = [ordered]@{
        base_python = $pythonPath
        direct_python = Join-Path $directVenv 'Scripts\python.exe'
        direct_console = Join-Path $directVenv 'Scripts\finplanbr.exe'
        sdist_python = Join-Path $rebuiltVenv 'Scripts\python.exe'
        sdist_console = Join-Path $rebuiltVenv 'Scripts\finplanbr.exe'
    }
    $index = 0
    foreach ($role in $programs.Keys) {
        if (-not [IO.Path]::IsPathFullyQualified($programs[$role])) {
            throw "firewall program target for $role is not absolute"
        }
        $ruleName = "finplanbr-portability-$nonce-$index"
        $preexisting = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $ruleName -ErrorAction SilentlyContinue)
        $firewallSnapshot.Add([pscustomobject]@{
            name = $ruleName
            preexisting_count = $preexisting.Count
        })
        if ($preexisting.Count -ne 0) {
            throw 'unique portability firewall rule name already exists'
        }
        # Journal the exact nonce-bound name before the mutating call so a
        # create-then-throw failure is still removed by finally.
        $ruleNames.Add($ruleName)
        New-NetFirewallRule -PolicyStore ActiveStore -Name $ruleName `
            -DisplayName "finplanbr portability $nonce $role" `
            -Group 'finplanbr-portability-ephemeral' -Enabled True -Profile Any `
            -Direction Outbound -Action Block -Program $programs[$role] | Out-Null
        $index++
    }

    $basePost = Invoke-PythonJson -Arguments @(
        $networkProbe, '--expect', 'blocked', '--nonce', $nonce
    )
    $basePostReport = $basePost.Text | ConvertFrom-Json
    if ($basePostReport.status -ne 'passed' -or $basePostReport.connected) {
        throw 'Windows firewall did not block the base interpreter'
    }

    Invoke-PythonJson -Arguments @(
        $validator, 'prepare',
        '--source-root', $repositoryRoot,
        '--freeze-report', $freezePath,
        '--work-root', $workRoot,
        '--python-minor', $PythonMinor,
        '--nonce', $nonce,
        '--state-out', $statePath
    ) -TimeoutSeconds 600 | Out-Null
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json

    $blockedRoles = [Collections.Generic.List[string]]::new()
    foreach ($role in @('direct_python', 'sdist_python')) {
        $post = Invoke-PythonJson -Arguments @(
            $networkProbe, '--expect', 'blocked', '--nonce', $nonce
        ) -Executable $programs[$role] -TimeoutSeconds 60
        if ($post.ReturnCode -ne 0) {
            throw "Windows firewall did not block $role"
        }
        $postReport = $post.Text | ConvertFrom-Json
        if ($postReport.status -ne 'passed' -or $postReport.connected) {
            throw "Windows firewall postcontrol was inactive for $role"
        }
        $blockedRoles.Add($role)
    }

    $boundary = @{
        format = 'finplanbr.windows-portability-boundary.v1'
        status = 'active'
        nonce = $nonce
        network = @{
            mechanism = 'windows_firewall_exact_program'
            policy_store = 'ActiveStore'
            direction = 'outbound'
            action = 'block'
            program_roles = @($programs.Keys)
            program_count = $programs.Count
            program_targets_absolute = $true
            rule_names = @($ruleNames)
            preexisting_rule_count = @($firewallSnapshot | Where-Object preexisting_count -ne 0).Count
            precontrol_connected = $true
            postcontrol_blocked = $true
            postcontrol_roles = @('base_python') + @($blockedRoles)
        }
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $denyRights = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $denyRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        $denyRights,
        $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Deny
    )
    foreach ($candidateRoot in $state.filesystem_roots) {
        $target = Assert-UnderWorkRoot -Path $candidateRoot
        $acl = Get-Acl -LiteralPath $target
        $aclBackups.Add($target, $acl.Sddl)
        [void]$acl.AddAccessRule($denyRule)
        Set-Acl -LiteralPath $target -AclObject $acl
    }
    $boundary.filesystem = @{
        mechanism = 'ntfs_acl_readonly_tested_trees'
        target_count = $aclBackups.Count
        targets_absolute = $true
        prior_sddl_snapshot_count = $aclBackups.Count
    }
    Write-Utf8NoBom -Path $boundaryPath -Text (($boundary | ConvertTo-Json -Compress -Depth 10) + "`n")

    Invoke-PythonJson -Arguments @(
        $validator, 'exercise',
        '--state', $statePath,
        '--boundary-report', $boundaryPath,
        '--exercise-out', $exercisePath
    ) -TimeoutSeconds 900 | Out-Null
}
catch {
    $phaseError = $_
}
finally {
    foreach ($target in @($aclBackups.Keys)) {
        try {
            $currentAcl = Get-Acl -LiteralPath $target
            $currentAcl.SetSecurityDescriptorSddlForm($aclBackups[$target])
            Set-Acl -LiteralPath $target -AclObject $currentAcl
            if ((Get-Acl -LiteralPath $target).Sddl -ne $aclBackups[$target]) {
                $aclRestored = $false
            }
        }
        catch {
            $aclRestored = $false
        }
    }
    foreach ($ruleName in @($ruleNames)) {
        try {
            Remove-NetFirewallRule -PolicyStore ActiveStore -Name $ruleName -ErrorAction Stop
        }
        catch {
            $firewallRulesAbsent = $false
        }
    }
    foreach ($ruleName in @($ruleNames)) {
        if (Get-NetFirewallRule -PolicyStore ActiveStore -Name $ruleName -ErrorAction SilentlyContinue) {
            $firewallRulesAbsent = $false
        }
    }
    if ($cleanupPath) {
        $cleanup = @{
            format = 'finplanbr.windows-portability-cleanup.v1'
            nonce = $nonce
            firewall_rules_absent = $firewallRulesAbsent
            acl_restored = $aclRestored
        }
        Write-Utf8NoBom -Path $cleanupPath -Text (($cleanup | ConvertTo-Json -Compress) + "`n")
    }
}

if ($phaseError) {
    $failure = @{
        format = 'finplanbr.installed-portability-host-launch.v1'
        status = 'failed'
        cell = $cell
        error_type = $phaseError.Exception.GetType().Name
        error = $phaseError.Exception.Message
        firewall_cleanup_verified = $firewallRulesAbsent
        acl_cleanup_verified = $aclRestored
        audit_hook_fallback = $false
        authority = 'none'
        release_authorized = $false
    }
    if ($workCreated) {
        $validatedWork = [IO.Path]::GetFullPath($workRoot)
        $expectedPrefix = $tempRoot + '\finplanbr-portability-windows-'
        if ($validatedWork.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $validatedWork -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Emit-Report -ReturnCode 1 -Report $failure
}
if (-not $firewallRulesAbsent -or -not $aclRestored) {
    Emit-Report -ReturnCode 1 -Report @{
        format = 'finplanbr.installed-portability-host-launch.v1'
        status = 'failed'
        cell = $cell
        reason = 'boundary_cleanup_not_verified'
        firewall_cleanup_verified = $firewallRulesAbsent
        acl_cleanup_verified = $aclRestored
        authority = 'none'
        release_authorized = $false
    }
}

$final = Invoke-PythonJson -Arguments @(
    $validator, 'finalize',
    '--exercise-report', $exercisePath,
    '--cleanup-report', $cleanupPath
)
$finalReport = $final.Text | ConvertFrom-Json
if ($finalReport.status -ne 'passed') {
    throw 'Windows finalized evidence did not pass'
}
if ($workCreated) {
    $validatedWork = [IO.Path]::GetFullPath($workRoot)
    $expectedPrefix = $tempRoot + '\finplanbr-portability-windows-'
    if (-not $validatedWork.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'refusing to remove an unvalidated Windows portability work root'
    }
    Remove-Item -LiteralPath $validatedWork -Recurse -Force
}
if ($OutputPath) {
    $target = Assert-OutsideRepository -Path $OutputPath
    $parent = Split-Path -Parent $target
    if ($parent) {
        [IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    Write-Utf8NoBom -Path $target -Text ($final.Text + "`n")
}
[Console]::Out.WriteLine($final.Text)
exit 0
