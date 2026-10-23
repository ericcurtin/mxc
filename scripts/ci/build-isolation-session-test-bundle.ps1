<#
.SYNOPSIS
Builds the isolation-session test bundle for one Windows architecture.

.DESCRIPTION
Builds the in-process Rust tests, the apartment probe, the self-contained .NET
SDK tests and the Node SDK integration suite, stages them beside wxc-exec, a
Node runtime and the PowerShell suites, and checks that every payload
discovers its tests.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('x64', 'arm64')]
    [string]$Architecture,

    [Parameter(Mandatory)]
    [string]$OutputDirectory,

    [Parameter(Mandatory)]
    [string]$Pipeline,

    [Parameter(Mandatory)]
    [string]$BranchName,

    [Parameter(Mandatory)]
    [string]$SourceRef,

    [Parameter(Mandatory)]
    [string]$BuildId,

    [string]$Package,

    # Built with the isolation_session feature when not supplied.
    [string]$WxcExecPath,

    [string]$NuGetSource
)

$ErrorActionPreference = 'Stop'

$triple = @{ x64 = 'x86_64-pc-windows-msvc'; arm64 = 'aarch64-pc-windows-msvc' }[$Architecture]
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$srcRoot = Join-Path $repoRoot 'src'

. (Join-Path $PSScriptRoot 'test-bundle-helpers.ps1')

if (Test-Path -LiteralPath $OutputDirectory) {
    Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
}
$OutputDirectory = New-Directory $OutputDirectory

$sdkPackage = @('-p', 'mxc-sdk', '--features', 'isolation_session')
if (-not $WxcExecPath) {
    $WxcExecPath = Get-CargoExecutable (Invoke-CargoBuild $srcRoot $triple @('build', '-p', 'wxc', '--features', 'isolation_session')) 'wxc-exec'
}
$testArtifacts = Invoke-CargoBuild $srcRoot $triple (@('test') + $sdkPackage + @('--test', 'isolation_session', '--test', 'sdk_helpers', '--no-run'))
$probeArtifacts = Invoke-CargoBuild $srcRoot $triple (@('build') + $sdkPackage + @('--example', 'sta_probe'))
$nativeLibrary = Get-CargoLibrary (Invoke-CargoBuild $srcRoot $triple @('build', '-p', 'mxc_ffi', '--features', 'isolation_session')) 'mxc_ffi'

Copy-NodeIntegrationSuite -RepoRoot $repoRoot -Architecture $Architecture `
    -NativeFiles @($WxcExecPath, $nativeLibrary) `
    -TestFiles @('isolation-session-*.test.js') -OutputDirectory $OutputDirectory
$integrationOut = Join-Path $OutputDirectory 'sdk-integration'

$dotnetOut = Join-Path $OutputDirectory 'dotnet'
$publish = @(
    'publish', (Join-Path $repoRoot 'sdk\dotnet\Microsoft.Mxc.Sdk.Tests\Microsoft.Mxc.Sdk.Tests.csproj'),
    '-c', 'Release', '-r', "win-$Architecture", '-p:MxcWithIsolationSession=true',
    '--self-contained', 'true', '-o', $dotnetOut, '--nologo'
)
if ($NuGetSource) {
    $publish += @('--source', $NuGetSource)
}
Invoke-Checked 'dotnet publish' { dotnet @publish }

Copy-Item -LiteralPath $WxcExecPath -Destination (New-Directory (Join-Path $OutputDirectory "bin\$Architecture"))

$inproc = New-Directory (Join-Path $OutputDirectory 'inproc')
Copy-Item -LiteralPath (Get-CargoExecutable $testArtifacts 'isolation_session') -Destination (Join-Path $inproc 'mxc-sdk-isolation-session-tests.exe')
Copy-Item -LiteralPath (Get-CargoExecutable $testArtifacts 'sdk_helpers') -Destination (Join-Path $inproc 'mxc-sdk-helpers-tests.exe')
Copy-Item -LiteralPath (Get-CargoExecutable $probeArtifacts 'sta_probe') -Destination (Join-Path $inproc 'sta_probe.exe')

Copy-Item -Path (Join-Path $repoRoot 'tests\configs\isolation_session_*.json') -Destination (New-Directory (Join-Path $OutputDirectory 'test_configs'))
$scriptsOut = New-Directory (Join-Path $OutputDirectory 'test_scripts')
foreach ($name in 'run_isolation_session_tests.ps1', 'run_isolation_session_state_aware_tests.ps1', 'run_isolation_session_resize_smoke.ps1') {
    Copy-Item -LiteralPath (Join-Path $repoRoot "tests\scripts\$name") -Destination $scriptsOut
}
$helperPaths = @(& (Join-Path $PSScriptRoot 'stage-isolation-session-test-helpers.ps1') `
    -SourceDirectory (Join-Path $repoRoot 'tests\scripts') -ScriptsDirectory $scriptsOut)

$manifest = [ordered]@{
    format_version = 1
    produced_at    = [DateTime]::UtcNow.ToString('o')
    branch_name    = $BranchName
    source_ref     = $SourceRef
    commit_sha     = (git -C $repoRoot rev-parse HEAD).Trim()
    build_id       = $BuildId
    pipeline       = $Pipeline
    triplet        = $triple
    features       = @('isolation_session', 'dotnetsdk', 'node-sdk-integration')
}
if ($Package) {
    $manifest['package'] = $Package
}
$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'manifest.json') -Encoding utf8

$required = @(
    'manifest.json',
    "bin\$Architecture\wxc-exec.exe",
    'inproc\mxc-sdk-isolation-session-tests.exe',
    'inproc\mxc-sdk-helpers-tests.exe',
    'inproc\sta_probe.exe',
    'dotnet\Microsoft.Mxc.Sdk.Tests.exe',
    'dotnet\mxc_ffi.dll',
    'dotnet\plm.exe',
    'node\node.exe',
    'node\LICENSE',
    'sdk-integration\package.json',
    'sdk-integration\run-tests.js',
    'sdk-integration\dist\isolation-session-state-aware.test.js',
    'test_scripts\run_isolation_session_tests.ps1',
    'test_scripts\run_isolation_session_state_aware_tests.ps1',
    'test_scripts\run_isolation_session_resize_smoke.ps1'
)
$required += @($helperPaths | ForEach-Object { Join-Path 'test_scripts' $_ })
Assert-BundleFiles -OutputDirectory $OutputDirectory -RelativePaths $required
if (-not (Get-ChildItem -LiteralPath (Join-Path $OutputDirectory 'test_configs') -Filter '*.json')) {
    throw 'The bundle has no isolation-session test configs.'
}

Assert-Discovery 'in-process tests' '(?m)^[1-9][0-9]* tests, 0 benchmarks\r?$' {
    & (Join-Path $inproc 'mxc-sdk-isolation-session-tests.exe') --list
}
Assert-Discovery 'SDK helper tests' '(?m)^[1-9][0-9]* tests, 0 benchmarks\r?$' {
    & (Join-Path $inproc 'mxc-sdk-helpers-tests.exe') --list
}
Assert-Discovery '.NET tests' 'Microsoft\.Mxc\.Sdk\.Tests' {
    & (Join-Path $dotnetOut 'Microsoft.Mxc.Sdk.Tests.exe') -list full
}
Push-Location $integrationOut
$env:MXC_SKIP_OS_BUILD_DEPENDENT_TESTS = '1'
try {
    Assert-Discovery 'Node SDK integration suite' '(?m)^[^A-Za-z0-9]*tests\s+[1-9][0-9]*\r?$' {
        & (Join-Path $OutputDirectory 'node\node.exe') --test --test-force-exit dist/isolation-session-state-aware.test.js
    }
}
finally {
    Remove-Item Env:MXC_SKIP_OS_BUILD_DEPENDENT_TESTS
    Pop-Location
}

$ErrorActionPreference = 'Continue'
$global:LASTEXITCODE = 0
$probeOutput = (& (Join-Path $inproc 'sta_probe.exe') invalid 2>&1 | ForEach-Object { "$_" }) -join "`n"
$probeExit = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($probeExit -ne 2 -or $probeOutput -notmatch 'unknown mode: invalid') {
    throw "The packaged apartment probe did not start (exit $probeExit): $probeOutput"
}
$global:LASTEXITCODE = 0

Write-Host "Isolation-session test bundle for $Architecture staged at $OutputDirectory"
