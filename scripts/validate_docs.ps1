param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [object[]]$GateArguments
)

$processArguments = [System.Environment]::GetCommandLineArgs()
$executableName = [System.IO.Path]::GetFileName($processArguments[0])
$knownHost = (
    [System.String]::Equals($executableName, 'powershell.exe', [System.StringComparison]::OrdinalIgnoreCase) -or
    [System.String]::Equals($executableName, 'powershell', [System.StringComparison]::OrdinalIgnoreCase) -or
    [System.String]::Equals($executableName, 'pwsh.exe', [System.StringComparison]::OrdinalIgnoreCase) -or
    [System.String]::Equals($executableName, 'pwsh', [System.StringComparison]::OrdinalIgnoreCase) -or
    [System.String]::Equals($executableName, 'pwsh.dll', [System.StringComparison]::OrdinalIgnoreCase)
)

# The accepted process grammar is deliberately lexical. PowerShell's parameter binder is
# case-insensitive and accepts abbreviations, so it cannot establish canonical invocation.
$scriptPathIndex = -1
$modeIndex = -1
if (
    $processArguments.Length -eq 6 -and
    [System.String]::Equals($processArguments[1], '-NoProfile', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[2], '-File', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[4], '-Mode', [System.StringComparison]::Ordinal)
) {
    $scriptPathIndex = 3
    $modeIndex = 5
}
elseif (
    $processArguments.Length -eq 7 -and
    [System.String]::Equals($processArguments[1], '-NoProfile', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[2], '-NonInteractive', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[3], '-File', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[5], '-Mode', [System.StringComparison]::Ordinal)
) {
    $scriptPathIndex = 4
    $modeIndex = 6
}
elseif (
    $processArguments.Length -eq 8 -and
    [System.String]::Equals($processArguments[1], '-NoProfile', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[2], '-ExecutionPolicy', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[3], 'Bypass', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[4], '-File', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[6], '-Mode', [System.StringComparison]::Ordinal)
) {
    $scriptPathIndex = 5
    $modeIndex = 7
}
elseif (
    $processArguments.Length -eq 9 -and
    [System.String]::Equals($processArguments[1], '-NoProfile', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[2], '-NonInteractive', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[3], '-ExecutionPolicy', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[4], 'Bypass', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[5], '-File', [System.StringComparison]::Ordinal) -and
    [System.String]::Equals($processArguments[7], '-Mode', [System.StringComparison]::Ordinal)
) {
    $scriptPathIndex = 6
    $modeIndex = 8
}

$canonicalMode = $false
$canonicalPath = $false
if ($scriptPathIndex -ge 0 -and $modeIndex -ge 0) {
    $rawMode = [string]$processArguments[$modeIndex]
    $canonicalMode = (
        [System.String]::Equals($rawMode, 'Structure', [System.StringComparison]::Ordinal) -or
        [System.String]::Equals($rawMode, 'F0', [System.StringComparison]::Ordinal) -or
        [System.String]::Equals($rawMode, 'Release00', [System.StringComparison]::Ordinal) -or
        [System.String]::Equals($rawMode, 'Release01', [System.StringComparison]::Ordinal)
    )

    $rawScriptPath = [string]$processArguments[$scriptPathIndex]
    $containsParentTraversal = $false
    foreach ($pathSegment in [System.Text.RegularExpressions.Regex]::Split($rawScriptPath, '[\\/]')) {
        if ([System.String]::Equals($pathSegment, '..', [System.StringComparison]::Ordinal)) {
            $containsParentTraversal = $true
        }
    }
    try {
        $resolvedScriptPath = [System.IO.Path]::GetFullPath($rawScriptPath)
        $actualScriptPath = [System.IO.Path]::GetFullPath($PSCommandPath)
        $pathComparison = if ([System.IO.Path]::DirectorySeparatorChar -eq '\') {
            [System.StringComparison]::OrdinalIgnoreCase
        }
        else {
            [System.StringComparison]::Ordinal
        }
        $sameScript = [System.String]::Equals($resolvedScriptPath, $actualScriptPath, $pathComparison)
        $documentedRelativePath = (
            [System.String]::Equals($rawScriptPath, './scripts/validate_docs.ps1', [System.StringComparison]::Ordinal) -or
            [System.String]::Equals($rawScriptPath, '.\scripts\validate_docs.ps1', [System.StringComparison]::Ordinal)
        )
        $canonicalAbsolutePath = (
            [System.IO.Path]::IsPathRooted($rawScriptPath) -and
            [System.String]::Equals($rawScriptPath, $actualScriptPath, $pathComparison)
        )
        $canonicalPath = -not $containsParentTraversal -and $sameScript -and ($documentedRelativePath -or $canonicalAbsolutePath)
    }
    catch {
        $canonicalPath = $false
    }
}

if (-not $knownHost -or -not $canonicalMode -or -not $canonicalPath) {
    [System.Console]::Error.WriteLine('validate_docs.ps1 refused a non-canonical invocation; use a fresh powershell or pwsh process with -NoProfile -File <gate> -Mode <mode>. No consistency or authority decision was attempted.')
    [System.Environment]::Exit(2)
}

$Mode = [string]$processArguments[$modeIndex]
if (-not [System.String]::Equals($Mode, 'Structure', [System.StringComparison]::Ordinal)) {
    if ([System.String]::Equals($Mode, 'F0', [System.StringComparison]::Ordinal)) {
        [System.Console]::Error.WriteLine('Local consistency check failed in F0 mode with 4 issue(s):')
    }
    elseif ([System.String]::Equals($Mode, 'Release00', [System.StringComparison]::Ordinal)) {
        [System.Console]::Error.WriteLine('Local consistency check failed in Release00 mode with 5 issue(s):')
    }
    else {
        [System.Console]::Error.WriteLine('Local consistency check failed in Release01 mode with 6 issue(s):')
    }
    [System.Console]::Error.WriteLine(' - External release authority is not implemented or integrated; candidate-side tooling cannot satisfy F0, Release00, Release01, promotion, or release authority')
    [System.Console]::Error.WriteLine(' - Local Apache-2.0 decision and LICENSE do not authenticate external F0 or release authority')
    [System.Console]::Error.WriteLine(' - Local maintainer roster does not authenticate an independent human reviewer')
    [System.Console]::Error.WriteLine(' - Local governance does not authorize F0, package publication, or release')
    if (
        [System.String]::Equals($Mode, 'Release00', [System.StringComparison]::Ordinal) -or
        [System.String]::Equals($Mode, 'Release01', [System.StringComparison]::Ordinal)
    ) {
        [System.Console]::Error.WriteLine(' - Release00 is unavailable: external math-conformance authority is not implemented; run the local math self-check only as a separate non-authoritative diagnostic')
    }
    if ([System.String]::Equals($Mode, 'Release01', [System.StringComparison]::Ordinal)) {
        [System.Console]::Error.WriteLine(' - Release01 is unavailable: external closed artifact inspection and release authority are not implemented')
    }
    [System.Environment]::Exit(1)
}

function Test-ExistingNonReparsePathChain {
    param(
        [string]$Path,
        [ValidateSet('Any', 'File', 'Directory')]
        [string]$Kind = 'Any'
    )

    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $existsAsFile = [System.IO.File]::Exists($fullPath)
        $existsAsDirectory = [System.IO.Directory]::Exists($fullPath)
        if (-not $existsAsFile -and -not $existsAsDirectory) {
            return $false
        }
        if ($Kind -eq 'File' -and -not $existsAsFile) {
            return $false
        }
        if ($Kind -eq 'Directory' -and -not $existsAsDirectory) {
            return $false
        }

        $current = $fullPath
        while ($null -ne $current) {
            $attributes = [System.IO.File]::GetAttributes($current)
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
            $parent = [System.IO.Directory]::GetParent($current)
            $current = if ($null -eq $parent) { $null } else { $parent.FullName }
        }
        return $true
    }
    catch {
        return $false
    }
}

function Test-PathStrictlyBelow {
    param(
        [string]$Candidate,
        [string]$Root,
        [System.StringComparison]$Comparison
    )

    try {
        $fullCandidate = [System.IO.Path]::GetFullPath($Candidate)
        $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
        $rootPrefix = $fullRoot + [System.IO.Path]::DirectorySeparatorChar
        return $fullCandidate.StartsWith($rootPrefix, $Comparison)
    }
    catch {
        return $false
    }
}

# Structure can import built-in modules only after the process host has crossed a
# Windows-specific, OS-protected path boundary. This is deliberately not a claim
# that a compromised administrator or PowerShell engine has been authenticated.
$hostTrustEstablished = $false
$hostTrustLimit = 'validate_docs.ps1 host trust is limited to Windows OS-protected installation paths and non-reparse path metadata; it cannot authenticate a compromised administrator or PowerShell engine.'
$managementModule = $null
$utilityModule = $null
$fsutilExecutable = $null
if ([System.IO.Path]::DirectorySeparatorChar -eq '\') {
    try {
        $pathComparison = [System.StringComparison]::OrdinalIgnoreCase
        $windowsRoot = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows)
        $programFilesRoot = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles)
        $processExecutable = [System.IO.Path]::GetFullPath(
            [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        )
        $powerShellHome = [System.IO.Path]::GetFullPath([string]$PSHOME).TrimEnd('\', '/')
        $processHome = [System.IO.Directory]::GetParent($processExecutable).FullName.TrimEnd('\', '/')
        $argumentHostPath = [System.IO.Path]::GetFullPath([string]$processArguments[0])
        $managementModule = [System.IO.Path]::Combine($powerShellHome, 'Modules', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Management.psd1')
        $utilityModule = [System.IO.Path]::Combine($powerShellHome, 'Modules', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Utility.psd1')
        $fsutilExecutable = [System.IO.Path]::Combine($windowsRoot, 'System32', 'fsutil.exe')

        $coherentHome = [System.String]::Equals($processHome, $powerShellHome, $pathComparison)
        $trustedHostLocation = $false
        $coherentArgumentHost = $false
        if ([System.String]::Equals([string]$PSVersionTable.PSEdition, 'Desktop', [System.StringComparison]::Ordinal)) {
            $expectedHome = [System.IO.Path]::Combine($windowsRoot, 'System32', 'WindowsPowerShell', 'v1.0')
            $expectedExecutable = [System.IO.Path]::Combine($expectedHome, 'powershell.exe')
            $trustedHostLocation = (
                [System.String]::Equals($processExecutable, $expectedExecutable, $pathComparison) -and
                [System.String]::Equals($powerShellHome, $expectedHome, $pathComparison)
            )
            $coherentArgumentHost = [System.String]::Equals($argumentHostPath, $expectedExecutable, $pathComparison)
        }
        elseif ([System.String]::Equals([string]$PSVersionTable.PSEdition, 'Core', [System.StringComparison]::Ordinal)) {
            $programFilesPowerShell = [System.IO.Path]::Combine($programFilesRoot, 'PowerShell')
            $windowsApps = [System.IO.Path]::Combine($programFilesRoot, 'WindowsApps')
            $trustedHostLocation = (
                [System.String]::Equals([System.IO.Path]::GetFileName($processExecutable), 'pwsh.exe', $pathComparison) -and
                (
                    (Test-PathStrictlyBelow $processExecutable $programFilesPowerShell $pathComparison) -or
                    (Test-PathStrictlyBelow $processExecutable $windowsApps $pathComparison)
                )
            )
            $expectedArgumentHost = [System.IO.Path]::Combine($powerShellHome, 'pwsh.dll')
            $coherentArgumentHost = [System.String]::Equals($argumentHostPath, $expectedArgumentHost, $pathComparison)
        }

        $hostTrustEstablished = (
            -not [string]::IsNullOrWhiteSpace($windowsRoot) -and
            -not [string]::IsNullOrWhiteSpace($programFilesRoot) -and
            $coherentHome -and
            $trustedHostLocation -and
            $coherentArgumentHost -and
            (Test-ExistingNonReparsePathChain $processExecutable 'File') -and
            (Test-ExistingNonReparsePathChain $argumentHostPath 'File') -and
            (Test-ExistingNonReparsePathChain $powerShellHome 'Directory') -and
            (Test-ExistingNonReparsePathChain $managementModule 'File') -and
            (Test-ExistingNonReparsePathChain $utilityModule 'File') -and
            (Test-ExistingNonReparsePathChain $fsutilExecutable 'File')
        )
    }
    catch {
        $hostTrustEstablished = $false
    }
}

if (-not $hostTrustEstablished) {
    [System.Console]::Error.WriteLine('validate_docs.ps1 could not establish its supported Windows PowerShell host trust boundary before module import. No consistency or authority decision was attempted.')
    [System.Console]::Error.WriteLine($hostTrustLimit)
    [System.Environment]::Exit(2)
}
[System.Console]::Error.WriteLine($hostTrustLimit)

$script:repoRoot = [System.IO.Directory]::GetParent([System.IO.Path]::GetFullPath($PSScriptRoot)).FullName.TrimEnd('\', '/')
$script:rootPrefix = $script:repoRoot + [System.IO.Path]::DirectorySeparatorChar
$repositoryPreflightFailures = [System.Collections.Generic.List[string]]::new()
if (-not (Test-ExistingNonReparsePathChain $script:repoRoot 'Directory')) {
    $repositoryPreflightFailures.Add('Structure repository root or one of its ancestors is missing, not a directory, or a symlink/junction/reparse point')
}
else {
    $requiredRepositoryDirectories = @(
        'scripts',
        'docs',
        'docs/governance',
        'docs/history',
        'docs/research',
        'docs/specification'
    )
    foreach ($relativeDirectory in $requiredRepositoryDirectories) {
        $requiredDirectory = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($script:repoRoot, $relativeDirectory))
        if (-not (Test-ExistingNonReparsePathChain $requiredDirectory 'Directory')) {
            $repositoryPreflightFailures.Add("Structure requires a local non-reparse directory and ancestor chain: $relativeDirectory")
        }
    }

    # Inspect each entry with System.IO and never push a reparse directory onto the
    # traversal stack. This prevents a candidate junction from exposing external docs.
    $pendingDirectories = [System.Collections.Generic.Stack[string]]::new()
    $pendingDirectories.Push($script:repoRoot)
    while ($pendingDirectories.Count -gt 0) {
        $currentDirectory = $pendingDirectories.Pop()
        try {
            foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries($currentDirectory)) {
                try {
                    $entryFullPath = [System.IO.Path]::GetFullPath($entry)
                    $entryAttributes = [System.IO.File]::GetAttributes($entryFullPath)
                    $entryRelativePath = $entryFullPath.Substring($script:repoRoot.Length).TrimStart('\', '/').Replace('\', '/')
                    if (($entryAttributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                        $repositoryPreflightFailures.Add("Structure repository tree contains a forbidden symlink/junction/reparse path: $entryRelativePath")
                        continue
                    }
                    if (($entryAttributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                        $pendingDirectories.Push($entryFullPath)
                    }
                }
                catch {
                    $repositoryPreflightFailures.Add("Structure cannot inspect repository tree entry '$entry': $($_.Exception.Message)")
                }
            }
        }
        catch {
            $relativeDirectory = if ([System.String]::Equals($currentDirectory, $script:repoRoot, $pathComparison)) { '.' } else { $currentDirectory.Substring($script:repoRoot.Length).TrimStart('\', '/').Replace('\', '/') }
            $repositoryPreflightFailures.Add("Structure cannot enumerate repository directory '$relativeDirectory': $($_.Exception.Message)")
        }
    }
}

if ($repositoryPreflightFailures.Count -gt 0) {
    [System.Console]::Error.WriteLine("Local consistency check failed in Structure mode with $($repositoryPreflightFailures.Count) issue(s):")
    foreach ($failure in $repositoryPreflightFailures) {
        [System.Console]::Error.WriteLine(" - $failure")
    }
    [System.Environment]::Exit(1)
}

# Disable discovery from caller-controlled module paths before the first command that
# PowerShell resolves by name, then import only the built-in modules by trusted path.
$PSModuleAutoLoadingPreference = 'None'
[System.Environment]::SetEnvironmentVariable('PSModulePath', [System.String]::Empty, [System.EnvironmentVariableTarget]::Process)
if (-not [System.IO.File]::Exists($managementModule) -or -not [System.IO.File]::Exists($utilityModule)) {
    [System.Console]::Error.WriteLine('validate_docs.ps1 could not locate trusted built-in PowerShell modules under PSHOME. No consistency decision was attempted.')
    [System.Environment]::Exit(2)
}
try {
    Microsoft.PowerShell.Core\Import-Module -Name $managementModule -Scope Local -Force -ErrorAction Stop
    Microsoft.PowerShell.Core\Import-Module -Name $utilityModule -Scope Local -Force -ErrorAction Stop
}
catch {
    [System.Console]::Error.WriteLine('validate_docs.ps1 could not import trusted built-in PowerShell modules under PSHOME. No consistency decision was attempted.')
    [System.Environment]::Exit(2)
}

$ErrorActionPreference = 'Stop'
$script:failures = [System.Collections.Generic.List[string]]::new()

function Add-Failure {
    param([string]$Message)
    $script:failures.Add($Message)
}

function Get-BytesSha256 {
    param([byte[]]$Bytes)

    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $hasher.ComputeHash($Bytes)
        return ([System.BitConverter]::ToString($digest)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
}

function Get-Win32FileId {
    param([string]$Path)

    if ($Path.Contains('"')) {
        throw "Structure cannot query a file id for a path containing a quote: $Path"
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $fsutilExecutable
    $startInfo.Arguments = 'file queryfileid "' + $Path + '"'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stdoutTask = $null
    $stderrTask = $null
    try {
        if (-not $process.Start()) {
            throw "trusted fsutil did not start for $Path"
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) {
            try { $process.Kill() } catch {}
            throw "trusted fsutil queryfileid timed out for $Path"
        }
        if (-not [System.Threading.Tasks.Task]::WaitAll(
            [System.Threading.Tasks.Task[]]@($stdoutTask, $stderrTask),
            5000
        )) {
            throw "trusted fsutil output readers did not close for $Path"
        }
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        if ($process.ExitCode -ne 0) {
            $stderrBytes = [Text.Encoding]::UTF8.GetBytes($stderr)
            throw "trusted fsutil queryfileid returned $($process.ExitCode) for ${Path}; stderr_sha256=$(Get-BytesSha256 $stderrBytes)"
        }
        $idMatch = [regex]::Match($stdout, '(?i)0x[0-9a-f]+')
        if (-not $idMatch.Success) {
            throw "trusted fsutil queryfileid returned no file id for $Path"
        }
        return $idMatch.Value.ToLowerInvariant()
    }
    finally {
        $process.Dispose()
    }
}

function ConvertTo-RepositoryRelativePath {
    param([string]$FullPath)

    $canonical = [System.IO.Path]::GetFullPath($FullPath)
    if ([System.String]::Equals($canonical, $script:repoRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return '.'
    }
    if (-not $canonical.StartsWith($script:rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Structure path is outside repository root: $FullPath"
    }
    return $canonical.Substring($script:rootPrefix.Length).Replace('\', '/')
}

function Get-RepositoryInventoryPaths {
    $paths = [System.Collections.Generic.List[string]]::new()
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($script:repoRoot)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        $paths.Add((ConvertTo-RepositoryRelativePath $directory))
        foreach ($entryPath in [System.IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $fullPath = [System.IO.Path]::GetFullPath($entryPath)
            if (-not (Test-InsideRepoRoot $fullPath)) {
                throw "Structure inventory escaped repository root: $entryPath"
            }
            $attributes = [System.IO.File]::GetAttributes($fullPath)
            $relativePath = ConvertTo-RepositoryRelativePath $fullPath
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Structure repository tree contains a forbidden symlink/junction/reparse path: $relativePath"
            }
            if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                $pending.Push($fullPath)
            }
            else {
                $paths.Add($relativePath)
            }
        }
    }

    [string[]]$ordered = $paths.ToArray()
    [System.Array]::Sort($ordered, [System.StringComparer]::Ordinal)
    return ,$ordered
}

function Get-RepositoryEntryIdentity {
    param(
        [string]$RelativePath,
        [string]$FullPath
    )

    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $FullPath -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Structure repository tree contains a forbidden symlink/junction/reparse path: $RelativePath"
    }
    $kind = if ($item.PSIsContainer) { 'directory' } else { 'regular_file' }
    if (-not $item.PSIsContainer -and -not [System.IO.File]::Exists($item.FullName)) {
        throw "Structure repository entry is not a direct regular file: $RelativePath"
    }

    # On the trusted Windows FileSystem provider, LinkType=HardLink is exposed
    # whenever a regular file has more than one directory entry. Refusing that
    # state closes the accepted regular-file boundary at nlink=1.
    $linkType = [string]$item.LinkType
    if (
        -not $item.PSIsContainer -and
        [System.String]::Equals($linkType, 'HardLink', [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "Structure requires every repository regular file to have nlink=1; hardlink detected: $RelativePath"
    }

    $streamItems = @(
        Microsoft.PowerShell.Management\Get-Item -LiteralPath $item.FullName -Stream '*' -Force -ErrorAction Stop
    )
    $streamStates = [System.Collections.Generic.List[string]]::new()
    foreach ($streamItem in $streamItems) {
        $streamName = [string]$streamItem.Stream
        $streamLength = [int64]$streamItem.Length
        if (-not [System.String]::Equals($streamName, ':$DATA', [System.StringComparison]::Ordinal)) {
            throw "Structure repository entry has a forbidden named/non-default Win32 alternate data stream: $RelativePath ($streamName)"
        }
        $streamStates.Add($streamName + ':' + $streamLength)
    }
    if ($item.PSIsContainer) {
        if ($streamStates.Count -ne 0) {
            throw "Structure repository directory exposes an unexpected default data stream: $RelativePath"
        }
    }
    else {
        if (
            $streamStates.Count -ne 1 -or
            -not [System.String]::Equals($streamStates[0], ':$DATA:' + [int64]$item.Length, [System.StringComparison]::Ordinal)
        ) {
            throw "Structure repository regular file lacks one exact default Win32 data stream: $RelativePath"
        }
    }

    [string[]]$orderedStreams = $streamStates.ToArray()
    [System.Array]::Sort($orderedStreams, [System.StringComparer]::Ordinal)
    $fileId = Get-Win32FileId $item.FullName
    $length = if ($item.PSIsContainer) { [int64]0 } else { [int64]$item.Length }
    $fingerprint = @(
        $kind,
        [System.IO.Path]::GetFullPath($item.FullName),
        $fileId,
        ([int64]$item.Attributes).ToString([System.Globalization.CultureInfo]::InvariantCulture),
        ([int64]$item.CreationTimeUtc.Ticks).ToString([System.Globalization.CultureInfo]::InvariantCulture),
        ([int64]$item.LastWriteTimeUtc.Ticks).ToString([System.Globalization.CultureInfo]::InvariantCulture),
        $length.ToString([System.Globalization.CultureInfo]::InvariantCulture),
        $linkType,
        ($orderedStreams -join ',')
    ) -join [char]0x001F

    return [pscustomobject]@{
        RelativePath = $RelativePath
        FullName = [System.IO.Path]::GetFullPath($item.FullName)
        Kind = $kind
        Length = $length
        FileId = $fileId
        LinkType = $linkType
        Streams = $orderedStreams
        Fingerprint = $fingerprint
    }
}

function New-RepositorySnapshot {
    try {
        [string[]]$inventoryBefore = Get-RepositoryInventoryPaths
        $entries = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $fileIds = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $fileCount = 0
        $directoryCount = 0

        foreach ($relativePath in $inventoryBefore) {
            $fullPath = if ([System.String]::Equals($relativePath, '.', [System.StringComparison]::Ordinal)) {
                $script:repoRoot
            }
            else {
                [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($script:repoRoot, $relativePath.Replace('/', '\')))
            }
            $identityBefore = Get-RepositoryEntryIdentity $relativePath $fullPath
            $bytes = $null
            $sha256 = $null
            if ([System.String]::Equals($identityBefore.Kind, 'regular_file', [System.StringComparison]::Ordinal)) {
                [byte[]]$bytes = [System.IO.File]::ReadAllBytes($identityBefore.FullName)
                $sha256 = Get-BytesSha256 $bytes
                $identityAfter = Get-RepositoryEntryIdentity $relativePath $fullPath
                if (-not [System.String]::Equals(
                    $identityBefore.Fingerprint,
                    $identityAfter.Fingerprint,
                    [System.StringComparison]::Ordinal
                )) {
                    throw "Structure repository entry drifted while its bytes were snapshotted: $relativePath"
                }
                if ($fileIds.ContainsKey($identityAfter.FileId)) {
                    throw "Structure requires nlink=1 file identity; '$relativePath' aliases '$($fileIds[$identityAfter.FileId])'"
                }
                $fileIds.Add($identityAfter.FileId, $relativePath)
                $identity = $identityAfter
                $fileCount++
            }
            else {
                $identity = $identityBefore
                $directoryCount++
            }

            $entries.Add($relativePath, [pscustomobject]@{
                RelativePath = $relativePath
                FullName = $identity.FullName
                Kind = $identity.Kind
                Length = $identity.Length
                FileId = $identity.FileId
                IdentityFingerprint = $identity.Fingerprint
                Bytes = $bytes
                Sha256 = $sha256
            })
        }

        [string[]]$inventoryAfter = Get-RepositoryInventoryPaths
        if ($inventoryBefore.Count -ne $inventoryAfter.Count) {
            throw "Structure repository inventory drifted while the snapshot was acquired"
        }
        for ($index = 0; $index -lt $inventoryBefore.Count; $index++) {
            if (-not [System.String]::Equals($inventoryBefore[$index], $inventoryAfter[$index], [System.StringComparison]::Ordinal)) {
                throw "Structure repository inventory drifted while the snapshot was acquired"
            }
        }

        return [pscustomobject]@{
            Inventory = $inventoryBefore
            Entries = $entries
            FileCount = $fileCount
            DirectoryCount = $directoryCount
        }
    }
    catch {
        Add-Failure "Structure could not acquire a stable repository byte/inventory/identity snapshot: $($_.Exception.Message)"
        return $null
    }
}

function Test-RepositorySnapshotUnchanged {
    param([object]$Snapshot)

    try {
        [string[]]$currentInventory = Get-RepositoryInventoryPaths
        if ($currentInventory.Count -ne $Snapshot.Inventory.Count) {
            Add-Failure "Structure repository snapshot drift detected in final inventory recheck"
            return $false
        }
        for ($index = 0; $index -lt $currentInventory.Count; $index++) {
            if (-not [System.String]::Equals(
                $currentInventory[$index],
                $Snapshot.Inventory[$index],
                [System.StringComparison]::Ordinal
            )) {
                Add-Failure "Structure repository snapshot drift detected in final inventory recheck"
                return $false
            }
        }

        $unchanged = $true
        foreach ($relativePath in $Snapshot.Inventory) {
            $expected = $Snapshot.Entries[$relativePath]
            try {
                $actualIdentity = Get-RepositoryEntryIdentity $relativePath $expected.FullName
                if (-not [System.String]::Equals(
                    $actualIdentity.Fingerprint,
                    $expected.IdentityFingerprint,
                    [System.StringComparison]::Ordinal
                )) {
                    Add-Failure "Structure repository snapshot drift detected in final identity recheck: $relativePath"
                    $unchanged = $false
                    continue
                }
                if ([System.String]::Equals($expected.Kind, 'regular_file', [System.StringComparison]::Ordinal)) {
                    [byte[]]$actualBytes = [System.IO.File]::ReadAllBytes($expected.FullName)
                    $actualSha256 = Get-BytesSha256 $actualBytes
                    if (-not [System.String]::Equals($actualSha256, $expected.Sha256, [System.StringComparison]::Ordinal)) {
                        Add-Failure "Structure repository snapshot drift detected in final byte recheck: $relativePath"
                        $unchanged = $false
                    }
                }
            }
            catch {
                Add-Failure "Structure repository snapshot drift detected while rechecking ${relativePath}: $($_.Exception.Message)"
                $unchanged = $false
            }
        }
        return $unchanged
    }
    catch {
        Add-Failure "Structure repository snapshot drift detected during final recheck: $($_.Exception.Message)"
        return $false
    }
}

function Write-StructureFailuresAndExit {
    if ($script:failures.Count -eq 0) {
        return
    }
    Microsoft.PowerShell.Utility\Write-Host "Local consistency check failed in Structure mode with $($script:failures.Count) issue(s):" -ForegroundColor Red
    foreach ($failure in $script:failures) {
        Microsoft.PowerShell.Utility\Write-Host " - $failure" -ForegroundColor Red
    }
    [System.Environment]::Exit(1)
}

$script:legacyMarkers = @('tbd', 'tbdbycounsel', 'todo', 'placeholder', 'fillthis')
$script:unresolvedMarkers = @('tbd', 'tbdbycounsel', 'todo', 'placeholder', 'fillthis', 'unknown', 'unassigned')

function ConvertTo-LfText {
    param([object]$Value)
    return ([string]$Value).Replace("`r`n", "`n").Replace("`r", "`n")
}

function Get-LinePreservingNormalizedText {
    param([object]$Value)
    $text = (ConvertTo-LfText $Value).Normalize([Text.NormalizationForm]::FormKC)
    return [regex]::Replace($text, '\p{Cf}', '')
}

function Get-NormalizedText {
    param([object]$Value)
    $text = Get-LinePreservingNormalizedText $Value
    $text = [regex]::Replace($text, '\s+', ' ').Trim()
    return $text.ToLowerInvariant()
}

function Get-NormalizedMarker {
    param([object]$Value)
    $normalized = Get-NormalizedText $Value
    return [regex]::Replace($normalized, '[\s\p{P}\p{S}]+', '')
}

function Test-LegacyMarker {
    param([object]$Value)
    $raw = [string]$Value
    $normalized = Get-NormalizedMarker $raw
    if ($normalized -in $script:legacyMarkers) {
        return $true
    }
    if ($normalized -in @('unknown', 'unassigned')) {
        return (Get-NormalizedText $raw) -cne $normalized
    }
    return $false
}

function Test-TextHasUnresolvedMarker {
    param([object]$Content)
    $text = ConvertTo-LfText $Content
    foreach ($line in ($text -split '\n')) {
        $normalized = Get-NormalizedText $line
        $normalized = [regex]::Replace($normalized, '^[#>*+\-\s`\[\](){}]+', '')
        $normalized = [regex]::Replace($normalized, '[*_`]+', '')
        $parts = $normalized -split '[:=]', 2
        $candidate = if ($parts.Count -eq 2 -and $parts[0] -match '^(status|decision|license|licen[çc]a|review|revis[aã]o|owner|respons[aá]vel)$') { $parts[1] } else { $normalized }
        if ((Get-NormalizedMarker $candidate) -in $script:legacyMarkers) {
            return $true
        }
    }
    return $false
}

function Test-UnresolvedValue {
    param([object]$Value)
    return (Get-NormalizedMarker $Value) -in $script:unresolvedMarkers
}

function Test-InsideRepoRoot {
    param([string]$Candidate)
    $fullPath = [System.IO.Path]::GetFullPath($Candidate)
    return ($fullPath -eq $script:repoRoot) -or $fullPath.StartsWith($script:rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

$script:repositorySnapshot = New-RepositorySnapshot
if ($null -eq $script:repositorySnapshot -or $script:failures.Count -gt 0) {
    Write-StructureFailuresAndExit
}
[System.Console]::Out.WriteLine(
    "Structure repository snapshot acquired: $($script:repositorySnapshot.FileCount) regular files and $($script:repositorySnapshot.DirectoryCount) directories with bytes, Win32 file identity, nlink=1, and no named ADS."
)
[System.Console]::Out.Flush()

function Assert-RequiredPath {
    param(
        [string]$RelativePath,
        [string]$Gate,
        [ValidateSet('Any', 'File', 'Directory')]
        [string]$Kind = 'Any',
        [int64]$MinimumBytes = 0
    )
    try {
        $candidate = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($script:repoRoot, $RelativePath.Replace('/', '\')))
        if (-not (Test-InsideRepoRoot $candidate)) {
            Add-Failure "$Gate path escapes repository root: $RelativePath"
            return $null
        }
        $snapshotRelative = ConvertTo-RepositoryRelativePath $candidate
        if (-not $script:repositorySnapshot.Entries.ContainsKey($snapshotRelative)) {
            Add-Failure "$Gate requires local path: $RelativePath"
            return $null
        }
        $item = $script:repositorySnapshot.Entries[$snapshotRelative]
        if ($Kind -eq 'File' -and -not [System.String]::Equals($item.Kind, 'regular_file', [System.StringComparison]::Ordinal)) {
            Add-Failure "$Gate requires a regular file, not a directory: $RelativePath"
            return $null
        }
        if ($Kind -eq 'Directory' -and -not [System.String]::Equals($item.Kind, 'directory', [System.StringComparison]::Ordinal)) {
            Add-Failure "$Gate requires a directory, not a file: $RelativePath"
            return $null
        }
        if ($Kind -eq 'File' -and $item.Length -lt $MinimumBytes) {
            Add-Failure "$Gate requires a non-trivial file at ${RelativePath}; found $($item.Length) byte(s), minimum is $MinimumBytes"
            return $null
        }
        return $item
    }
    catch {
        Add-Failure "$Gate cannot inspect local path ${RelativePath}: $($_.Exception.Message)"
        return $null
    }
}

function Get-TextFileContent {
    param(
        [string]$RelativePath,
        [string]$Gate
    )
    $item = Assert-RequiredPath $RelativePath $Gate 'File' 1
    if ($null -eq $item) {
        return $null
    }
    try {
        return [System.Text.UTF8Encoding]::new($false, $true).GetString([byte[]]$item.Bytes)
    }
    catch {
        Add-Failure "$Gate cannot read text file ${RelativePath}: $($_.Exception.Message)"
        return $null
    }
}

function Resolve-RegularRepoFile {
    param(
        [string]$RelativePath,
        [string]$Label
    )
    $trimmed = $RelativePath.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed) -or (Test-UnresolvedValue $trimmed)) {
        Add-Failure "$Label requires a resolved repository-relative artifact path"
        return $null
    }
    if ([System.IO.Path]::IsPathRooted($trimmed)) {
        Add-Failure "$Label artifact path must be repository-relative: $RelativePath"
        return $null
    }
    try {
        $candidate = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($script:repoRoot, $trimmed.Replace('/', '\')))
        if (-not (Test-InsideRepoRoot $candidate)) {
            Add-Failure "$Label artifact path escapes repository root: $RelativePath"
            return $null
        }
        $snapshotRelative = ConvertTo-RepositoryRelativePath $candidate
        if (-not $script:repositorySnapshot.Entries.ContainsKey($snapshotRelative)) {
            Add-Failure "$Label requires a local regular file: $RelativePath"
            return $null
        }
        $item = $script:repositorySnapshot.Entries[$snapshotRelative]
        if (-not [System.String]::Equals($item.Kind, 'regular_file', [System.StringComparison]::Ordinal)) {
            Add-Failure "$Label requires a local non-link regular file: $RelativePath"
            return $null
        }
        if ($item.Length -eq 0) {
            Add-Failure "$Label requires a non-empty local artifact: $RelativePath"
            return $null
        }
        return $item
    }
    catch {
        Add-Failure "$Label cannot inspect artifact path ${RelativePath}: $($_.Exception.Message)"
        return $null
    }
}

function Assert-ApprovedEvidence {
    param(
        [object]$Row,
        [string]$RelativePath,
        [string]$Id
    )
    $label = "$RelativePath approved record '$Id'"
    $checksum = ([string]$Row.source_checksum).Trim()
    if ($checksum -notmatch '^sha256:[0-9a-f]{64}$') {
        Add-Failure "$label lacks a lowercase sha256 checksum"
        return
    }
    if ($checksum -eq ('sha256:' + ('0' * 64))) {
        Add-Failure "$label uses the forbidden all-zero sha256 sentinel"
    }
    $artifact = Resolve-RegularRepoFile ([string]$Row.source_artifact_path) $label
    if ($null -ne $artifact) {
        if ($checksum.Substring(7) -ne $artifact.Sha256) {
            Add-Failure "$label checksum does not match source_artifact_path '$($Row.source_artifact_path)'"
        }
    }

    Add-Failure "$label is only a candidate-side approval assertion; Structure cannot authenticate reviewer identity or approval"

    if (-not (Test-IsoDay ([string]$Row.reviewed_on)) -or -not (Test-IsoDay ([string]$Row.review_expires_at))) {
        Add-Failure "$label lacks valid review and expiry dates"
    }
    else {
        $reviewedOn = [datetime]::ParseExact([string]$Row.reviewed_on, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
        $reviewExpiresAt = [datetime]::ParseExact([string]$Row.review_expires_at, 'yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
        $today = [datetime]::UtcNow.Date
        if ($reviewedOn -gt $today) {
            Add-Failure "$label has a review date in the future"
        }
        if ($reviewExpiresAt -lt $today) {
            Add-Failure "$label has an expired review assertion"
        }
    }
}

function Assert-Enum {
    param(
        [object[]]$Rows,
        [string]$Column,
        [string[]]$Allowed,
        [string]$RelativePath
    )
    foreach ($row in $Rows) {
        $value = [string]$row.$Column
        if ($value -notin $Allowed) {
            $id = [string]$row.PSObject.Properties[0].Value
            Add-Failure "$RelativePath has invalid $Column '$value' for '$id'; allowed: $($Allowed -join ', ')"
        }
    }
}

function Test-IsoDay {
    param([string]$Value)
    $parsed = [datetime]::MinValue
    return ($Value -match '^\d{4}-\d{2}-\d{2}$') -and [datetime]::TryParseExact(
        $Value,
        'yyyy-MM-dd',
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::None,
        [ref]$parsed
    )
}

function Assert-TemporalValue {
    param(
        [string]$Value,
        [string]$Precision,
        [bool]$AllowOpen,
        [string]$Label
    )

    if ($Value -eq 'unknown') {
        if ($Precision -ne 'unknown') {
            Add-Failure "$Label uses unknown value with precision '$Precision'"
        }
        return
    }
    if ($Value -eq 'open') {
        if (-not $AllowOpen -or $Precision -ne 'not_applicable') {
            Add-Failure "$Label uses open outside an open interval or without not_applicable precision"
        }
        return
    }

    switch ($Precision) {
        'day' {
            if (-not (Test-IsoDay $Value)) {
                Add-Failure "$Label must be a valid ISO day"
            }
        }
        'year' {
            if ($Value -notmatch '^\d{4}$') {
                Add-Failure "$Label must be a four-digit year"
            }
        }
        'datetime' {
            $parsed = [datetimeoffset]::MinValue
            if (($Value -notmatch '^\d{4}-\d{2}-\d{2}T') -or -not [datetimeoffset]::TryParse($Value, [ref]$parsed)) {
                Add-Failure "$Label must be an ISO datetime with offset"
            }
        }
        default {
            Add-Failure "$Label has incompatible precision '$Precision'"
        }
    }
}

function Assert-ReviewDates {
    param(
        [object]$Row,
        [string]$RelativePath
    )
    $id = [string]$Row.PSObject.Properties[0].Value
    foreach ($column in @('reviewed_on', 'review_expires_at')) {
        $value = [string]$Row.$column
        if ($value -ne 'unknown' -and -not (Test-IsoDay $value)) {
            Add-Failure "$RelativePath has invalid $column '$value' for '$id'"
        }
    }
    if ((Test-IsoDay ([string]$Row.reviewed_on)) -and (Test-IsoDay ([string]$Row.review_expires_at))) {
        if ([datetime]$Row.review_expires_at -lt [datetime]$Row.reviewed_on) {
            Add-Failure "$RelativePath has review expiry before review for '$id'"
        }
    }
}

$requiredDocuments = @(
    'AGENTS.md',
    'GOVERNANCE.md',
    'LICENSE',
    'MAINTAINERS.md',
    'README.md',
    'DISCLAIMER.md',
    'PRIVACY.md',
    'MODEL_RISK.md',
    'DATA_LICENSES.md',
    'docs/architecture.md',
    'docs/runbook.md',
    'docs/changelog-codex.md',
    'docs/governance/deployment-classification.md',
    'docs/history/trust-r2-r11-superseded.md',
    'docs/specification/policy-packs.md'
)
foreach ($relativePath in $requiredDocuments) {
    $null = Assert-RequiredPath $relativePath 'Structure' 'File' 1
}

$historyRelativePath = 'docs/history/trust-r2-r11-superseded.md'
$historyFullPath = [System.IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $script:repoRoot $historyRelativePath))
$historyExactH1 = 'HIST' + [char]0x00D3 + 'RICO SUPERADO ' + [char]0x2014 + ' N' + [char]0x00C3 + 'O EXECUT' + [char]0x00C1 + 'VEL'
$historyH2Prefix = $historyExactH1 + ' ' + [char]0x2014 + ' '
$historyH2TitleSeparator = ' ' + [char]0x2014 + ' '
$expectedHistoryH2Roster = @(
    ('R2' + [char]0x2013 + 'R3'),
    'R4',
    'R6',
    'R7',
    'R8',
    'R10',
    'R11'
)
$historyContent = Get-TextFileContent $historyRelativePath 'Structure superseded history contract'
if ($null -ne $historyContent) {
    $normalizedHistoryContent = $historyContent.Replace("`r`n", "`n").Replace("`r", "`n")
    $expectedHistoryFrontMatter = "---`nstatus: superseded`nexecutable: false`naccepted_by_gate: false`nauthority: none`n---`n"
    if (-not $normalizedHistoryContent.StartsWith($expectedHistoryFrontMatter, [System.StringComparison]::Ordinal)) {
        Add-Failure "$historyRelativePath front matter must be exactly status=superseded, executable=false, accepted_by_gate=false, authority=none, with no additional keys"
    }

    $historyH1Matches = [regex]::Matches($historyContent, '(?m)^# (?!#)([^\r\n]+)\r?$')
    if (
        $historyH1Matches.Count -ne 1 -or
        -not [System.String]::Equals(
            $historyH1Matches[0].Groups[1].Value,
            $historyExactH1,
            [System.StringComparison]::Ordinal
        )
    ) {
        Add-Failure "$historyRelativePath must contain the exact superseded/non-executable H1"
    }

    $historyH2Matches = [regex]::Matches($historyContent, '(?m)^## (?!#)([^\r\n]+)\r?$')
    $actualHistoryH2Roster = [System.Collections.Generic.List[string]]::new()
    foreach ($historyH2 in $historyH2Matches) {
        $historyH2Value = $historyH2.Groups[1].Value
        if (-not $historyH2Value.StartsWith($historyH2Prefix, [System.StringComparison]::Ordinal)) {
            Add-Failure "$historyRelativePath H2 is not explicitly invalidated: $historyH2Value"
            $actualHistoryH2Roster.Add('<invalid-prefix>')
            continue
        }

        $historyH2Remainder = $historyH2Value.Substring($historyH2Prefix.Length)
        $historyH2SeparatorIndex = $historyH2Remainder.IndexOf(
            $historyH2TitleSeparator,
            [System.StringComparison]::Ordinal
        )
        if ($historyH2SeparatorIndex -le 0) {
            $actualHistoryH2Roster.Add($historyH2Remainder)
        }
        else {
            $actualHistoryH2Roster.Add($historyH2Remainder.Substring(0, $historyH2SeparatorIndex))
        }
    }

    $historyH2RosterMatches = $actualHistoryH2Roster.Count -eq $expectedHistoryH2Roster.Count
    if ($historyH2RosterMatches) {
        for ($historyH2Index = 0; $historyH2Index -lt $expectedHistoryH2Roster.Count; $historyH2Index++) {
            if (-not [System.String]::Equals(
                $actualHistoryH2Roster[$historyH2Index],
                $expectedHistoryH2Roster[$historyH2Index],
                [System.StringComparison]::Ordinal
            )) {
                $historyH2RosterMatches = $false
                break
            }
        }
    }
    if (-not $historyH2RosterMatches) {
        Add-Failure "$historyRelativePath H2 roster must be exactly 7 entries in Ordinal order: $($expectedHistoryH2Roster -join ', '); found $($actualHistoryH2Roster.Count): $($actualHistoryH2Roster -join ', ')"
    }
}

$markdownFiles = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $script:repoRoot -Recurse -File -Filter '*.md')
foreach ($file in $markdownFiles) {
    $relativePath = if ($null -ne $file.PSObject.Properties['SnapshotRelative']) { [string]$file.SnapshotRelative } else { $file.FullName.Substring($script:repoRoot.Length).TrimStart('\', '/').Replace('\', '/') }
    $content = [string](Get-TextFileContent $relativePath 'Structure Markdown snapshot')

    if ([string]::IsNullOrWhiteSpace($content)) {
        Add-Failure "$relativePath is empty and cannot satisfy documentation structure"
    }
    if (Test-TextHasUnresolvedMarker $content) {
        Add-Failure "$relativePath contains a normalized standalone unresolved marker"
    }

    if (-not [System.String]::Equals($relativePath, $historyRelativePath, [System.StringComparison]::OrdinalIgnoreCase)) {
        # Compatibility normalization is deliberately line-preserving so anchored
        # heading scans cannot be bypassed with format controls or fullwidth forms.
        $normalizedScanContent = Get-LinePreservingNormalizedText $content
        $legacyProtocolMatches = [regex]::Matches(
            $normalizedScanContent,
            '(?i)\b(?:release-trust-policy|signed-person-registry|external-math-self-check-attestation|external-build-attestation|external-trust-bootstrap-result)\.v\d+\b'
        )
        foreach ($legacyProtocolMatch in $legacyProtocolMatches) {
            Add-Failure "$relativePath reintroduces legacy machine trust protocol id outside superseded history: $($legacyProtocolMatch.Value)"
        }

        foreach ($legacyHeading in [regex]::Matches($normalizedScanContent, '(?im)^#{1,6}[ \t]+R(?:[2-9]|10|11)(?=$|[ \t:\u2013\u2014-])[^\r\n]*')) {
            Add-Failure "$relativePath reintroduces an R2-R11 operational heading outside superseded history: $($legacyHeading.Value.Trim())"
        }
        $copiedHistoryHeadingPattern = '(?im)^#{2,6}[ \t]+' + [regex]::Escape($historyH2Prefix) + '[^\r\n]*'
        foreach ($copiedHistoryHeading in [regex]::Matches($normalizedScanContent, $copiedHistoryHeadingPattern)) {
            Add-Failure "$relativePath reinserts a superseded history section into current operational documentation: $($copiedHistoryHeading.Value.Trim())"
        }
    }

    $h1Count = ([regex]::Matches($content, '(?m)^# [^#]')).Count
    if ($h1Count -ne 1) {
        Add-Failure "$relativePath must contain exactly one H1; found $h1Count"
    }

    $fenceCount = ([regex]::Matches($content, '(?m)^```')).Count
    if (($fenceCount % 2) -ne 0) {
        Add-Failure "$relativePath has an unbalanced fenced code block"
    }

    $definitions = @{}
    foreach ($match in [regex]::Matches($content, '(?m)^\[\^([^\]]+)\]:')) {
        $definitions[$match.Groups[1].Value] = $true
    }
    foreach ($match in [regex]::Matches($content, '\[\^([^\]]+)\]')) {
        $footnoteId = $match.Groups[1].Value
        if (-not $definitions.ContainsKey($footnoteId)) {
            Add-Failure "$relativePath references undefined footnote [^$footnoteId]"
        }
    }

    foreach ($match in [regex]::Matches($content, '(?<!!)\[(?<label>[^\]]+)\]\((?<target>[^)]+)\)')) {
        $label = $match.Groups['label'].Value
        $target = $match.Groups['target'].Value.Trim()
        if ($target.StartsWith('<') -and $target.EndsWith('>')) {
            $target = $target.Substring(1, $target.Length - 2)
        }
        if ($target -match '^(https?://|mailto:|#)') {
            continue
        }

        try {
            $decodedTarget = [System.Uri]::UnescapeDataString($target)
        }
        catch {
            Add-Failure "$relativePath has invalid escaped local target '$target': $($_.Exception.Message)"
            continue
        }
        $targetParts = $decodedTarget -split '#', 2
        $targetPath = $targetParts[0]
        $hasFragment = $targetParts.Count -eq 2
        if ([string]::IsNullOrWhiteSpace($targetPath)) {
            continue
        }

        try {
            $resolvedPath = [System.IO.Path]::GetFullPath((Microsoft.PowerShell.Management\Join-Path $file.DirectoryName $targetPath))
            if (-not (Test-InsideRepoRoot $resolvedPath)) {
                Add-Failure "$relativePath links outside repository root: $target"
                continue
            }
            if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $resolvedPath)) {
                Add-Failure "$relativePath links to missing local target: $target"
                continue
            }
            $providerPath = (Microsoft.PowerShell.Management\Resolve-Path -LiteralPath $resolvedPath).ProviderPath
            if (-not (Test-InsideRepoRoot $providerPath)) {
                Add-Failure "$relativePath resolves outside repository root: $target"
            }
            if (
                -not [System.String]::Equals($relativePath, $historyRelativePath, [System.StringComparison]::OrdinalIgnoreCase) -and
                [System.String]::Equals([System.IO.Path]::GetFullPath($providerPath), $historyFullPath, $pathComparison)
            ) {
                if ($hasFragment) {
                    Add-Failure "$relativePath operational link to superseded history must not contain a fragment: $target"
                }
                $normalizedHistoryLabel = Get-NormalizedText $label
                $portugueseNotExecutable = 'n' + [char]0x00E3 + 'o execut' + [char]0x00E1 + 'vel'
                $invalidatingLabel = (
                    $normalizedHistoryLabel.Contains('invalidado') -or
                    $normalizedHistoryLabel.Contains('superado') -or
                    $normalizedHistoryLabel.Contains('superseded') -or
                    $normalizedHistoryLabel.Contains($portugueseNotExecutable) -or
                    $normalizedHistoryLabel.Contains('nao executavel') -or
                    $normalizedHistoryLabel.Contains('non-executable') -or
                    $normalizedHistoryLabel.Contains('not executable')
                )
                if (-not $invalidatingLabel) {
                    Add-Failure "$relativePath operational link to superseded history requires an explicitly invalidating label: [$label]"
                }
            }
        }
        catch {
            Add-Failure "$relativePath has invalid local target '$target': $($_.Exception.Message)"
        }
    }
}

$placeholderChecks = @(
    @{ Path = 'AGENTS.md'; Pattern = 'Fill this section' },
    @{ Path = 'docs/architecture.md'; Pattern = 'Define main components' },
    @{ Path = 'docs/runbook.md'; Pattern = 'Install dependencies' }
)
foreach ($check in $placeholderChecks) {
    $content = Get-TextFileContent $check.Path 'Structure'
    if ($null -ne $content -and $content -match [regex]::Escape($check.Pattern)) {
        Add-Failure "$($check.Path) still contains bootstrap placeholder: $($check.Pattern)"
    }
}

$forbiddenChecks = @(
    @{ Path = 'docs/research/financial-planning-sdk-br-sota.md'; Pattern = 'input.yaml' },
    @{ Path = 'docs/research/financial-planning-sdk-br-sota.md'; Pattern = 'livro-planejamento-financeiro-pessoal' },
    @{ Path = 'docs/research/financial-planning-sdk-br-sota.md'; Pattern = 'Sharkansky, M.' },
    @{ Path = 'docs/specification/mathematical-engine.md'; Pattern = '`valid_with_warnings`' },
    @{ Path = 'docs/specification/mathematical-engine.md'; Pattern = 'ES_t=' },
    @{ Path = 'docs/specification/mathematical-engine.md'; Pattern = 'K_T' }
)
foreach ($check in $forbiddenChecks) {
    $content = Get-TextFileContent $check.Path 'Structure'
    if ($null -ne $content -and $content.Contains($check.Pattern)) {
        Add-Failure "$($check.Path) contains superseded contract text: $($check.Pattern)"
    }
}

$positiveChecks = @(
    @{ Path = 'docs/governance/deployment-classification.md'; Patterns = @('GovernanceEnvelope', 'derived_minimum_deployment_class', 'REGULATED_USE_CLASS_MISMATCH') },
    @{ Path = 'docs/specification/policy-packs.md'; Patterns = @('court_clarification', 'scenario_only', 'artifact_status: draft | approved') },
    @{ Path = 'PRIVACY.md'; Patterns = @('dado potencialmente pessoal', 'nunca como anonimiza') },
    @{ Path = 'DATA_LICENSES.md'; Patterns = @('DATA_LICENSE_MANIFEST_MISSING', 'artifact_status`: `draft | approved') }
)
foreach ($check in $positiveChecks) {
    $content = Get-TextFileContent $check.Path 'Structure'
    if ($null -eq $content) {
        continue
    }
    foreach ($pattern in $check.Patterns) {
        if (-not $content.Contains($pattern)) {
            Add-Failure "$($check.Path) is missing required contract marker: $pattern"
        }
    }
}

$csvContracts = @(
    @{
        Path = 'docs/research/evidence-ledger.csv'
        Required = @('id', 'class', 'role', 'year', 'title', 'locator', 'verified_on')
    },
    @{
        Path = 'docs/research/software-comparator-manifest.csv'
        Required = @('id', 'repository', 'intended_role', 'license_observed', 'immutable_ref', 'status')
    },
    @{
        Path = 'docs/governance/regulatory-authority-ledger.csv'
        Required = @('authority_id', 'domain', 'jurisdiction', 'instrument_type', 'instrument_number', 'issued_at', 'issued_at_precision', 'published_at', 'published_at_precision', 'consolidated_through', 'official_url', 'official_pinpoint', 'role', 'legal_status', 'legal_certainty', 'policy_output_mode', 'source_artifact_path', 'source_checksum', 'reviewed_by', 'reviewed_on', 'review_expires_at', 'artifact_status', 'notes')
        Exact = $true
    },
    @{
        Path = 'docs/governance/legal-event-ledger.csv'
        Required = @('event_id', 'authority_id', 'event_type', 'announced_at', 'announced_at_precision', 'published_at', 'published_at_precision', 'valid_effect_from', 'valid_effect_from_precision', 'valid_effect_until', 'valid_effect_until_precision', 'known_from', 'known_from_precision', 'known_until', 'known_until_precision', 'retroactivity', 'affected_rule_ids', 'amends', 'supersedes', 'clarifies', 'suspends', 'restores', 'controlling_case_id', 'decision_stage', 'source_url', 'source_artifact_path', 'source_checksum', 'reviewed_by', 'reviewed_on', 'review_expires_at', 'artifact_status', 'status_notes')
        Exact = $true
    },
    @{
        Path = 'docs/governance/data-license-manifest.csv'
        Required = @('dataset_id', 'resource_id', 'licensor', 'source_url', 'license_id', 'license_text_url', 'license_version', 'contract_id', 'retrieved_at', 'observed_at', 'effective_at', 'source_artifact_path', 'source_checksum', 'privacy_class', 'automated_access', 'storage_allowed', 'redistribution', 'commercial_use', 'derivative_database', 'produced_work_notice', 'share_alike', 'machine_readable_offer', 'attribution_status', 'attribution_text', 'contract_expiry', 'reviewed_by', 'reviewed_on', 'review_expires_at', 'artifact_status', 'status_notes')
        Exact = $true
    }
)

$csvRowsByPath = @{}
foreach ($contract in $csvContracts) {
    $path = Microsoft.PowerShell.Management\Join-Path $script:repoRoot $contract.Path
    $csvItem = Assert-RequiredPath $contract.Path 'Structure CSV contract' 'File' 1
    if ($null -eq $csvItem) {
        continue
    }
    $path = $csvItem.FullName
    try {
        $csvText = Get-TextFileContent $contract.Path 'Structure CSV signed snapshot'
        if ($null -eq $csvText) { continue }
        $rows = @($csvText | Microsoft.PowerShell.Utility\ConvertFrom-Csv)
    }
    catch {
        Add-Failure "$($contract.Path) cannot be parsed as CSV: $($_.Exception.Message)"
        continue
    }
    $csvRowsByPath[$contract.Path] = $rows
    if ($rows.Count -eq 0) {
        Add-Failure "$($contract.Path) contains no data rows"
        continue
    }

    $columns = @($rows[0].PSObject.Properties.Name)
    foreach ($requiredColumn in $contract.Required) {
        if ($requiredColumn -notin $columns) {
            Add-Failure "$($contract.Path) is missing required column: $requiredColumn"
        }
    }
    if ($contract.Exact -and (($columns -join '|') -ne ($contract.Required -join '|'))) {
        Add-Failure "$($contract.Path) header must match the closed contract exactly and in order"
    }

    $firstColumn = $columns[0]
    foreach ($row in $rows) {
        $id = [string]$row.$firstColumn
        if ([string]::IsNullOrWhiteSpace($id)) {
            Add-Failure "$($contract.Path) contains a blank $firstColumn"
        }
        foreach ($property in $row.PSObject.Properties) {
            if (Test-LegacyMarker $property.Value) {
                Add-Failure "$($contract.Path) uses legacy marker '$($property.Value)' in $($property.Name) for '$id'"
            }
        }
    }

    $duplicates = $rows | Microsoft.PowerShell.Utility\Group-Object -Property $firstColumn | Microsoft.PowerShell.Core\Where-Object Count -gt 1
    foreach ($duplicate in $duplicates) {
        Add-Failure "$($contract.Path) has duplicate ${firstColumn}: $($duplicate.Name)"
    }
}

$authorityPath = 'docs/governance/regulatory-authority-ledger.csv'
$eventPath = 'docs/governance/legal-event-ledger.csv'
$dataPath = 'docs/governance/data-license-manifest.csv'
$authorityRows = @($csvRowsByPath[$authorityPath])
$eventRows = @($csvRowsByPath[$eventPath])
$dataRows = @($csvRowsByPath[$dataPath])

Assert-Enum $authorityRows 'issued_at_precision' @('day', 'year', 'unknown') $authorityPath
Assert-Enum $authorityRows 'published_at_precision' @('day', 'year', 'unknown') $authorityPath
Assert-Enum $authorityRows 'domain' @('investment_advice', 'iof_vgbl', 'open_finance', 'open_insurance', 'pension_tax', 'portfolio_management', 'privacy', 'securities_analysis', 'social_security', 'suitability') $authorityPath
Assert-Enum $authorityRows 'jurisdiction' @('BR') $authorityPath
Assert-Enum $authorityRows 'instrument_type' @('CNSP_resolution', 'constitutional_amendment', 'constitutional_case', 'CVM_resolution', 'federal_decree', 'federal_law', 'INSS_normative_instruction', 'joint_resolution', 'legislative_decree', 'RFB_normative_instruction', 'SUSEP_circular') $authorityPath
Assert-Enum $authorityRows 'role' @('primary', 'perimeter_check', 'legal_event') $authorityPath
Assert-Enum $authorityRows 'legal_status' @('not_yet_effective', 'in_force', 'partially_in_force', 'suspended', 'revoked', 'expired', 'unknown') $authorityPath
Assert-Enum $authorityRows 'legal_certainty' @('final', 'provisional', 'contested', 'unknown') $authorityPath
Assert-Enum $authorityRows 'policy_output_mode' @('definitive', 'scenario_only', 'blocked') $authorityPath
Assert-Enum $authorityRows 'artifact_status' @('draft', 'approved') $authorityPath

$authorityIds = @{}
foreach ($row in $authorityRows) {
    $id = [string]$row.authority_id
    $authorityIds[$id] = $true
    Assert-TemporalValue ([string]$row.issued_at) ([string]$row.issued_at_precision) $false "$authorityPath issued_at for '$id'"
    Assert-TemporalValue ([string]$row.published_at) ([string]$row.published_at_precision) $false "$authorityPath published_at for '$id'"
    Assert-ReviewDates $row $authorityPath
    if ($row.legal_certainty -eq 'contested' -and $row.policy_output_mode -ne 'scenario_only') {
        Add-Failure "$authorityPath requires scenario_only for contested authority '$id'"
    }
    if ($row.legal_certainty -eq 'unknown' -and $row.policy_output_mode -ne 'blocked') {
        Add-Failure "$authorityPath requires blocked output for unknown certainty '$id'"
    }
    if ($row.artifact_status -eq 'approved') {
        Assert-ApprovedEvidence $row $authorityPath $id
        if ($row.legal_status -eq 'unknown' -or $row.legal_certainty -eq 'unknown' -or $row.policy_output_mode -eq 'blocked') {
            Add-Failure "$authorityPath approved authority '$id' retains a blocked legal state"
        }
    }
}

Assert-Enum $eventRows 'event_type' @('enact', 'amend', 'revoke', 'suspend', 'restore', 'court_order', 'court_clarification', 'interpretive_guidance', 'correct') $eventPath
foreach ($precisionColumn in @('announced_at_precision', 'published_at_precision', 'valid_effect_from_precision', 'valid_effect_until_precision', 'known_from_precision', 'known_until_precision')) {
    Assert-Enum $eventRows $precisionColumn @('day', 'year', 'datetime', 'unknown', 'not_applicable') $eventPath
}
Assert-Enum $eventRows 'retroactivity' @('none', 'ex_nunc', 'ex_tunc', 'custom') $eventPath
Assert-Enum $eventRows 'decision_stage' @('final', 'provisional', 'ad_referendum', 'administrative_guidance') $eventPath
Assert-Enum $eventRows 'artifact_status' @('draft', 'approved') $eventPath

$eventIds = @{}
foreach ($row in $eventRows) {
    $eventIds[[string]$row.event_id] = $true
}
foreach ($row in $eventRows) {
    $id = [string]$row.event_id
    if (-not $authorityIds.ContainsKey([string]$row.authority_id)) {
        Add-Failure "$eventPath has missing authority FK '$($row.authority_id)' for '$id'"
    }
    Assert-TemporalValue ([string]$row.announced_at) ([string]$row.announced_at_precision) $false "$eventPath announced_at for '$id'"
    Assert-TemporalValue ([string]$row.published_at) ([string]$row.published_at_precision) $false "$eventPath published_at for '$id'"
    Assert-TemporalValue ([string]$row.valid_effect_from) ([string]$row.valid_effect_from_precision) $false "$eventPath valid_effect_from for '$id'"
    Assert-TemporalValue ([string]$row.valid_effect_until) ([string]$row.valid_effect_until_precision) $true "$eventPath valid_effect_until for '$id'"
    Assert-TemporalValue ([string]$row.known_from) ([string]$row.known_from_precision) $false "$eventPath known_from for '$id'"
    Assert-TemporalValue ([string]$row.known_until) ([string]$row.known_until_precision) $true "$eventPath known_until for '$id'"
    Assert-ReviewDates $row $eventPath
    if ((Test-IsoDay ([string]$row.announced_at)) -and (Test-IsoDay ([string]$row.published_at)) -and ([datetime]$row.published_at -lt [datetime]$row.announced_at)) {
        Add-Failure "$eventPath has publication before announcement for '$id'"
    }
    if ((Test-IsoDay ([string]$row.published_at)) -and (Test-IsoDay ([string]$row.known_from)) -and ([datetime]$row.known_from -lt [datetime]$row.published_at)) {
        Add-Failure "$eventPath has knowledge before publication for '$id'"
    }
    if ((Test-IsoDay ([string]$row.valid_effect_from)) -and (Test-IsoDay ([string]$row.valid_effect_until)) -and ([datetime]$row.valid_effect_until -lt [datetime]$row.valid_effect_from)) {
        Add-Failure "$eventPath has valid-effect interval reversed for '$id'"
    }

    foreach ($column in @('amends', 'supersedes', 'clarifies', 'suspends', 'restores')) {
        foreach ($reference in ([string]$row.$column -split '\|')) {
            if ($reference -eq 'none') {
                continue
            }
            if ($reference -match '^authority:(.+)$') {
                if (-not $authorityIds.ContainsKey($Matches[1])) {
                    Add-Failure "$eventPath has missing authority relationship FK '$reference' in $column for '$id'"
                }
            }
            elseif ($reference -match '^event:(.+)$') {
                if (-not $eventIds.ContainsKey($Matches[1])) {
                    Add-Failure "$eventPath has missing event relationship FK '$reference' in $column for '$id'"
                }
            }
            else {
                Add-Failure "$eventPath has untyped relationship '$reference' in $column for '$id'"
            }
            if ($column -eq 'clarifies' -and $reference -notmatch '^event:') {
                Add-Failure "$eventPath requires clarifies to reference an event for '$id'"
            }
        }
    }

    if ($row.event_type -eq 'court_clarification') {
        if ([string]$row.clarifies -eq 'none') {
            Add-Failure "$eventPath court clarification '$id' must clarify an existing event"
        }
        foreach ($forbiddenRelationship in @('amends', 'supersedes', 'suspends', 'restores')) {
            if ([string]$row.$forbiddenRelationship -ne 'none') {
                Add-Failure "$eventPath court clarification '$id' cannot set $forbiddenRelationship; it may only clarify an event"
            }
        }
    }
    elseif ([string]$row.clarifies -ne 'none') {
        Add-Failure "$eventPath only court_clarification events may set clarifies for '$id'"
    }

    if ($row.artifact_status -eq 'approved') {
        Assert-ApprovedEvidence $row $eventPath $id
        foreach ($column in @('valid_effect_from', 'valid_effect_until', 'reviewed_on', 'review_expires_at')) {
            if ([string]$row.$column -eq 'unknown') {
                Add-Failure "$eventPath approved event '$id' retains unknown $column"
            }
        }
    }
}

$dlgAuthority = $authorityRows | Microsoft.PowerShell.Core\Where-Object authority_id -eq 'BR-DLG-176'
if (@($dlgAuthority).Count -ne 1 -or $dlgAuthority.published_at -ne '2025-06-27' -or $dlgAuthority.published_at_precision -ne 'day') {
    Add-Failure "$authorityPath must record BR-DLG-176 publication as 2025-06-27 with day precision"
}
$dlgEvent = $eventRows | Microsoft.PowerShell.Core\Where-Object event_id -eq 'BR-IOF-2025-SUSPEND-DLG176'
if (@($dlgEvent).Count -ne 1 -or $dlgEvent.published_at -ne '2025-06-27' -or $dlgEvent.known_from -ne '2025-06-27') {
    Add-Failure "$eventPath must separate BR-DLG-176 promulgation from publication/knowledge on 2025-06-27"
}
$clarification = $eventRows | Microsoft.PowerShell.Core\Where-Object event_id -eq 'BR-IOF-2025-COURT-CLARIFY-GAP'
if (
    @($clarification).Count -ne 1 -or
    $clarification.event_type -ne 'court_clarification' -or
    $clarification.clarifies -ne 'event:BR-IOF-2025-COURT-RESTORE-PARTIAL' -or
    $clarification.amends -ne 'none' -or
    $clarification.supersedes -ne 'none' -or
    $clarification.suspends -ne 'none' -or
    $clarification.restores -ne 'none'
) {
    Add-Failure "$eventPath must model BR-IOF-2025-COURT-CLARIFY-GAP only as clarification of BR-IOF-2025-COURT-RESTORE-PARTIAL"
}

Assert-Enum $dataRows 'privacy_class' @('public_aggregate', 'public_market', 'public_regulated_entity', 'contractual_market', 'personal_financial', 'personal_financial_or_sensitive', 'personal_regulatory') $dataPath
foreach ($rightsColumn in @('automated_access', 'storage_allowed', 'redistribution', 'commercial_use', 'derivative_database')) {
    Assert-Enum $dataRows $rightsColumn @('allowed', 'restricted', 'contract_required', 'prohibited', 'unknown', 'not_applicable') $dataPath
}
foreach ($obligationColumn in @('produced_work_notice', 'share_alike', 'machine_readable_offer')) {
    Assert-Enum $dataRows $obligationColumn @('required', 'not_required', 'conditional', 'contract_required', 'unknown', 'not_applicable') $dataPath
}
Assert-Enum $dataRows 'attribution_status' @('provided', 'required', 'contract_required', 'unknown', 'not_applicable') $dataPath
Assert-Enum $dataRows 'artifact_status' @('draft', 'approved') $dataPath

$requiredDatasets = @('br.b3.customer_positions', 'br.anbima.calendar', 'br.inss.cnis')
$datasetIds = @{}
foreach ($row in $dataRows) {
    $id = [string]$row.dataset_id
    $datasetIds[$id] = $true
    foreach ($column in @('retrieved_at', 'observed_at', 'effective_at', 'contract_expiry', 'reviewed_on', 'review_expires_at')) {
        $value = [string]$row.$column
        if ($value -notin @('unknown', 'not_applicable') -and -not (Test-IsoDay $value)) {
            Add-Failure "$dataPath has invalid $column '$value' for '$id'"
        }
    }
    Assert-ReviewDates $row $dataPath
    if ($row.attribution_status -eq 'not_applicable' -and $row.attribution_text -ne 'not_applicable') {
        Add-Failure "$dataPath requires not_applicable attribution_text for '$id'"
    }
    if ($row.attribution_status -eq 'provided' -and $row.attribution_text -in @('unknown', 'not_applicable', '')) {
        Add-Failure "$dataPath requires actual attribution_text when provided for '$id'"
    }
    if ($row.artifact_status -eq 'approved') {
        foreach ($column in @('source_url', 'license_id', 'license_version', 'source_checksum', 'reviewed_by', 'reviewed_on', 'review_expires_at', 'automated_access', 'storage_allowed', 'redistribution', 'commercial_use', 'derivative_database')) {
            if ([string]$row.$column -in @('unknown', 'unassigned', '')) {
                Add-Failure "$dataPath approved dataset '$id' retains unresolved $column"
            }
        }
        if ($row.source_url -notmatch '^https://') {
            Add-Failure "$dataPath approved dataset '$id' lacks an HTTPS resource URL"
        }
        Assert-ApprovedEvidence $row $dataPath $id
    }
}
foreach ($requiredDataset in $requiredDatasets) {
    if (-not $datasetIds.ContainsKey($requiredDataset)) {
        Add-Failure "$dataPath is missing fail-closed resource: $requiredDataset"
    }
}

if ($script:failures.Count -gt 0) {
    Microsoft.PowerShell.Utility\Write-Host "Local consistency check failed in $Mode mode with $($script:failures.Count) issue(s):" -ForegroundColor Red
    foreach ($failure in $script:failures) {
        Microsoft.PowerShell.Utility\Write-Host " - $failure" -ForegroundColor Red
    }
    exit 1
}

Microsoft.PowerShell.Utility\Write-Host "Local consistency check passed in $Mode mode: $($markdownFiles.Count) Markdown files and $($csvContracts.Count) CSV contracts. This is not release authority." -ForegroundColor Green
