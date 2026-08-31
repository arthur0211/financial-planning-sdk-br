[CmdletBinding()]
param(
    [ValidateSet('Text', 'Json')]
    [string]$OutputFormat = 'Text',
    [switch]$SkipMutations
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runner = Join-Path $repoRoot 'scripts\validate_sdk_conformance.py'
$python = @(Get-Command python -CommandType Application -ErrorAction Stop)[0].Source
$arguments = @('-I', '-S', '-B', $runner, '--output-format', $OutputFormat.ToLowerInvariant())
if ($SkipMutations) {
    $arguments += '--skip-mutations'
}

& $python @arguments
exit $LASTEXITCODE
