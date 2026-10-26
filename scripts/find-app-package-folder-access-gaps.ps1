# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 5.1

<#
.SYNOPSIS
    Finds immediate subfolders without an applicable application-package grant.

.DESCRIPTION
    Defaults to checking the immediate subfolders of the Windows WinSxS directory
    for ALL_APPLICATION_PACKAGES grants. Includes hidden/system folders and both
    explicit and inherited ACEs, excluding inherit-only ACEs from folder access.
    Uses get-app-package-folder-access.ps1 to evaluate grants and denies.

    Returns only exceptions: NoApplicableGrant means the selected group's ACEs
    grant no rights on that folder. Unknown means an ACL could not be read or a
    directory reparse point was skipped; it does not mean access was denied.
    Does not inspect deeper descendants or test effective process access.
    A difference between directory and summary-row counts does not necessarily
    imply that exactly one immediate subfolder lacks a grant.

.PARAMETER Path
    Directory whose immediate subfolders should be checked.

.PARAMETER Principal
    Package group to inspect. Defaults to ALL_APPLICATION_PACKAGES.

.EXAMPLE
    .\scripts\find-app-package-folder-access-gaps.ps1

.EXAMPLE
    .\scripts\find-app-package-folder-access-gaps.ps1 -Path C:\Windows\WinSxS |
        Export-Csv -LiteralPath .\app-package-access-gaps.csv -NoTypeInformation -Encoding UTF8
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Path = (Join-Path $env:SystemRoot 'WinSxS'),

    [ValidateSet('ALL_APPLICATION_PACKAGES', 'ALL_RESTRICTED_APPLICATION_PACKAGES')]
    [string]$Principal = 'ALL_APPLICATION_PACKAGES'
)

Set-StrictMode -Version 2.0

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This script requires Windows.'
}

$scanner = Join-Path $PSScriptRoot 'get-app-package-folder-access.ps1'
$root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
if ($root -isnot [IO.DirectoryInfo]) {
    throw "'$Path' is not a filesystem directory."
}

$directories = @(Get-ChildItem -LiteralPath $root.FullName -Directory -Force -ErrorAction Stop |
    Sort-Object -Property FullName)
$scanPaths = @($directories | Where-Object {
    -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
} | Select-Object -ExpandProperty FullName)
$outcomes = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)

if ($scanPaths.Count -gt 0) {
    & $scanner -Path $scanPaths -Summary -NoRecurse -Principal $Principal |
        ForEach-Object { $outcomes.Add($_.Path, $_) }
}

$unknownCount = 0
$missingCount = 0
foreach ($directory in $directories) {
    $status = $null
    $note = $null
    if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        $status = 'Unknown'
        $note = 'Directory reparse point was not followed.'
    }
    elseif (-not $outcomes.ContainsKey($directory.FullName)) {
        $status = 'Unknown'
        $note = 'The ACL scan did not return a result for this folder.'
    }
    elseif ($outcomes[$directory.FullName].Scope -eq 'Unknown') {
        $status = 'Unknown'
        $note = $outcomes[$directory.FullName].Note
    }
    elseif ($outcomes[$directory.FullName].AccessMask -eq '0x00000000') {
        $status = 'NoApplicableGrant'
        $note = 'No rights granted by applicable ACEs for the selected group.'
    }

    if ($null -ne $status) {
        if ($status -eq 'Unknown') {
            $unknownCount++
        }
        else {
            $missingCount++
        }
        [pscustomobject][ordered]@{
            Path      = $directory.FullName
            Principal = $Principal
            Status    = $status
            Note      = $note
        }
    }
}

Write-Verbose "Checked $($directories.Count) immediate subfolders; $missingCount lack a grant; $unknownCount are unknown."
if ($unknownCount -gt 0) {
    Write-Warning "$unknownCount subfolders could not be classified. See the Unknown rows and the error stream."
}
