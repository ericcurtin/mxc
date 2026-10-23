<#
.SYNOPSIS
Builds the WSLC SDK test bundle for one Windows architecture.

.DESCRIPTION
Builds the self-contained .NET SDK tests and the Node SDK integration suite
with WSLC support, stages them beside a Node runtime, and checks that every
payload discovers its WSLC tests. The WSLC command-line suites run from the
build artifact itself, so they are not part of this bundle.
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

$nativeLibrary = Get-CargoLibrary (Invoke-CargoBuild $srcRoot $triple @('build', '-p', 'mxc_ffi', '--features', 'wslc')) 'mxc_ffi'
$daemon = Get-CargoExecutable (Invoke-CargoBuild $srcRoot $triple @('build', '-p', 'mxc-sdk', '--features', 'wslc', '--bin', 'wxc-wslc-daemon')) 'wxc-wslc-daemon'

# The wslc build feature stages the SDK library beside the daemon.
$wslcSdk = Join-Path (Split-Path -Parent $daemon) 'wslcsdk.dll'

Copy-NodeIntegrationSuite -RepoRoot $repoRoot -Architecture $Architecture `
    -NativeFiles @($nativeLibrary, $daemon, $wslcSdk) `
    -TestFiles @('wslc-state-aware.test.js') -OutputDirectory $OutputDirectory
$integrationOut = Join-Path $OutputDirectory 'sdk-integration'

$dotnetOut = Join-Path $OutputDirectory 'dotnet'
$publish = @(
    'publish', (Join-Path $repoRoot 'sdk\dotnet\Microsoft.Mxc.Sdk.Tests\Microsoft.Mxc.Sdk.Tests.csproj'),
    '-c', 'Release', '-r', "win-$Architecture", '-p:MxcWithWslc=true',
    '--self-contained', 'true', '-o', $dotnetOut, '--nologo'
)
if ($NuGetSource) {
    $publish += @('--source', $NuGetSource)
}
Invoke-Checked 'dotnet publish' { dotnet @publish }

$manifest = [ordered]@{
    format_version = 1
    produced_at    = [DateTime]::UtcNow.ToString('o')
    branch_name    = $BranchName
    source_ref     = $SourceRef
    commit_sha     = (git -C $repoRoot rev-parse HEAD).Trim()
    build_id       = $BuildId
    pipeline       = $Pipeline
    triplet        = $triple
    features       = @('wslc', 'dotnetsdk', 'node-sdk-integration')
}
$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'manifest.json') -Encoding utf8

$sdkBin = "sdk-integration\node_modules\@microsoft\mxc-sdk\bin\$Architecture"
Assert-BundleFiles -OutputDirectory $OutputDirectory -RelativePaths @(
    'manifest.json',
    'dotnet\Microsoft.Mxc.Sdk.Tests.exe',
    'dotnet\mxc_ffi.dll',
    'dotnet\wxc-wslc-daemon.exe',
    'dotnet\wslcsdk.dll',
    'node\node.exe',
    'node\LICENSE',
    'sdk-integration\package.json',
    'sdk-integration\run-tests.js',
    'sdk-integration\dist\wslc-state-aware.test.js',
    "$sdkBin\mxc_ffi.dll",
    "$sdkBin\wxc-wslc-daemon.exe",
    "$sdkBin\wslcsdk.dll"
)

Assert-Discovery '.NET WSLC tests' 'MxcLifecycleWslcE2ETests' {
    & (Join-Path $dotnetOut 'Microsoft.Mxc.Sdk.Tests.exe') -list full
}
Push-Location $integrationOut
try {
    Assert-Discovery 'Node SDK WSLC integration suite' '(?m)^[^A-Za-z0-9]*tests\s+[1-9][0-9]*\r?$' {
        & (Join-Path $OutputDirectory 'node\node.exe') --test --test-force-exit dist/wslc-state-aware.test.js
    }
}
finally {
    Pop-Location
}

Write-Host "WSLC SDK test bundle for $Architecture staged at $OutputDirectory"
