# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TargetTriple,
    [Parameter(Mandatory)][string]$TargetDirectory
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\TestSuiteResults.ps1')
$sourceDirectory = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'src'

Push-Location $sourceDirectory
try {
    $version = & rustc --version --verbose
    if ($LASTEXITCODE -ne 0) { throw 'Could not identify the native Rust host.' }
    $hostLine = @($version | Select-String -Pattern '^host: ')
    if ($hostLine.Count -ne 1) { throw 'Rust did not report exactly one native host.' }
    $nativeTriple = $hostLine[0].Line.Substring('host: '.Length).Trim()
    if ($TargetTriple -cne $nativeTriple) {
        throw "W365 pipe checks require a native runner: target '$TargetTriple', host '$nativeTriple'."
    }

    New-Item -ItemType Directory -Path $TargetDirectory -Force | Out-Null
    $TargetDirectory = (Resolve-Path -LiteralPath $TargetDirectory).Path
    $packages = @('-p', 'mxc-sdk', '-p', 'mxc_ffi')
    if ($IsWindows) { $packages += @('-p', 'wxc') }
    $common = @('--locked', '--no-default-features', '--target', $TargetTriple, '--target-dir', $TargetDirectory)
    foreach ($enabled in @($false, $true)) {
        $arguments = @('check', '--all-targets') + $common + $packages
        if ($enabled) { $arguments += @('--features', 'w365_agents') }
        & cargo @arguments
        if ($LASTEXITCODE -ne 0) { throw "Native package check failed (w365_agents=$enabled)." }
    }

    $scope = 'backend_modules::w365agents::common::exec::pipes::tests'
    $required = @(
        "${scope}::w365_pipe_workers_cancel_blocked_read",
        "${scope}::w365_pipe_workers_cancel_blocked_write",
        "${scope}::w365_pipe_workers_do_not_start_io_after_cancel",
        "${scope}::w365_pipe_workers_preserve_binary_data_eof_and_late_cancel",
        "${scope}::w365_pipe_workers_report_broken_output_in_foreign_hosts",
        "${scope}::w365_pipe_workers_survive_concurrent_drop_and_cancel",
        "${scope}::w365_pipe_watchdog_reaps_stalled_child"
    )
    $scenarios = @('blocked_read', 'blocked_write', 'cancel_before_io', 'data_eof_late_cancel', 'broken_output', 'drop_cancel_race')
    if ($IsWindows) {
        $required += @(
            "${scope}::w365_pipe_retries_cancel_before_kernel_read_issuance",
            "${scope}::w365_pipe_retries_cancel_before_kernel_write_issuance",
            "${scope}::w365_pipe_classifies_windows_relayed_input_without_consuming_it"
        )
        $inputScope = 'backend_modules::w365agents::common::exec::pipes::platform::input::tests'
        $required += @(
            "${inputScope}::w365_pipe_null_name_requires_exact_device_identity",
            "${inputScope}::w365_pipe_null_name_rejects_malformed_native_replies"
        )
        $scenarios += @('read_issuance_race', 'write_issuance_race', 'input_pipe', 'input_closed', 'input_null',
            'input_disk', 'input_overlapped', 'input_console', 'input_unproven_character')
    }

    $log = Join-Path $TargetDirectory 'w365-pipe-tests.log'
    $arguments = @('test') + $common + @('--features', 'w365_agents', '-p', 'mxc-sdk',
        '--lib', 'w365_pipe_', '--', '--show-output', '--color', 'never', '--test-threads=1')
    & cargo @arguments 2>&1 | Tee-Object -FilePath $log
    $run = @{ ExitCode = $LASTEXITCODE; Log = $log }
    $failure = Get-LibtestFailure -Run $run -RequiredTests $required
    if ($failure) { throw "W365 pipe gate $failure. See $log." }
    foreach ($scenario in $scenarios) {
        $pattern = '^' + [regex]::Escape("W365_PIPE_PROBE_OK:$scenario") + '\r?$'
        if (-not (Select-String -LiteralPath $log -Pattern $pattern)) {
            throw "W365 child scenario '$scenario' did not complete. See $log."
        }
    }
} finally {
    Pop-Location
}
