[CmdletBinding()]
param(
    [string]$VectorRoot = "",
    [string]$SutCommand = "",
    [string]$SutModule = "",
    [string]$SutModuleRoot = "",
    [string]$SutMutantsManifest = "",
    [string]$SutMutantsManifestSha256 = "",
    [string]$OracleBundleManifest = "",
    [string]$OracleBundleManifestSha256 = "",
    [ValidateSet("text", "json")]
    [string]$OutputFormat = "text",
    [double]$SutTimeoutSeconds = 5,
    [int]$SutStdoutLimit = 1048576,
    [int]$SutStderrLimit = 65536,
    [ValidateSet("forbid", "allow")]
    [string]$SutStderrPolicy = "forbid",
    [Alias("Reference")]
    [switch]$SelfCheck,
    [switch]$UpdateFingerprints,
    [switch]$SkipProperties,
    [Alias("SkipMutations")]
    [switch]$SkipReferenceSensitivity
)

$ErrorActionPreference = "Stop"
if ($SelfCheck -and (-not [string]::IsNullOrWhiteSpace($SutCommand) -or -not [string]::IsNullOrWhiteSpace($SutModule))) {
    throw "-SelfCheck cannot be combined with -SutCommand or -SutModule."
}
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$arguments = @((Join-Path $PSScriptRoot "validate_math_vectors.py"))

if (-not [string]::IsNullOrWhiteSpace($VectorRoot)) {
    $arguments += @("--vector-root", $VectorRoot)
}
if (-not [string]::IsNullOrWhiteSpace($SutCommand)) {
    $arguments += @("--sut-command", $SutCommand)
}
if (-not [string]::IsNullOrWhiteSpace($SutModule)) {
    $arguments += @("--sut-module", $SutModule)
}
if (-not [string]::IsNullOrWhiteSpace($SutModuleRoot)) {
    $arguments += @("--sut-module-root", $SutModuleRoot)
}
if (-not [string]::IsNullOrWhiteSpace($SutMutantsManifest)) {
    $arguments += @("--sut-mutants-manifest", $SutMutantsManifest)
}
if (-not [string]::IsNullOrWhiteSpace($SutMutantsManifestSha256)) {
    $arguments += @("--sut-mutants-manifest-sha256", $SutMutantsManifestSha256)
}
if (-not [string]::IsNullOrWhiteSpace($OracleBundleManifest)) {
    $arguments += @("--oracle-bundle-manifest", $OracleBundleManifest)
}
if (-not [string]::IsNullOrWhiteSpace($OracleBundleManifestSha256)) {
    $arguments += @("--oracle-bundle-manifest-sha256", $OracleBundleManifestSha256)
}
$arguments += @("--output-format", $OutputFormat)
$arguments += @("--sut-timeout-seconds", $SutTimeoutSeconds)
$arguments += @("--sut-stdout-limit", $SutStdoutLimit)
$arguments += @("--sut-stderr-limit", $SutStderrLimit)
$arguments += @("--sut-stderr-policy", $SutStderrPolicy)
if ($SelfCheck -or ([string]::IsNullOrWhiteSpace($SutCommand) -and [string]::IsNullOrWhiteSpace($SutModule))) {
    $arguments += "--self-check"
}
if ($UpdateFingerprints) { $arguments += "--update-fingerprints" }
if ($SkipProperties) { $arguments += "--skip-properties" }
if ($SkipReferenceSensitivity) { $arguments += "--skip-reference-sensitivity" }

Push-Location $repositoryRoot
try {
    & python @arguments
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
