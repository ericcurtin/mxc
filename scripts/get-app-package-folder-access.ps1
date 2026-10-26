# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 5.1

<#
.SYNOPSIS
    Finds folder ACL entries for the two built-in application-package groups.

.DESCRIPTION
    Reads folder permissions without changing them. By default, scans every
    formatted local fixed, removable, optical, or RAM volume, including volumes
    mounted in folders. Use -Path to scan selected filesystem directories instead.

    By default, returns one object per matching Allow or Deny entry for either
    package group, including inherited entries. AppliesToFolder is false for
    inherit-only entries.

    With -Summary, reports applicable rights for one group, defaulting to
    ALL_APPLICATION_PACKAGES. Combines applicable ACEs in DACL order, including
    inherited ACEs, and excludes inherit-only ACEs from the folder's rights.
    Collapses a directory tree only when the directory and every descendant
    directory have identical rights and deny masks for that group. Whether
    those permissions were explicit or inherited does not affect collapsing.

    Summary Scope is Subtree for a fully inspected uniform directory tree,
    ThisFolder for a grant that cannot represent its descendants, or Unknown
    for an unreadable or skipped branch. FolderCount counts directories covered
    by a known row. Separately specified roots are summarized independently.
    Subtree never makes a claim about files inside those directories.
    With -NoRecurse, only the specified roots are inspected and summary grants
    always have Scope ThisFolder, including zero-rights rows when no applicable
    grant exists.

    With -IgnoreEmpty, summary excludes directories confirmed to have no entries,
    including hidden/system entries. Subtree then covers only the included
    directories; IgnoredEmptyFolderCount records empty directories excluded
    beneath that subtree. Their own permissions and any future contents are not
    covered. Unreadable directories are never assumed empty.

    This inventories rights through the selected package group, not effective
    access for an application. Other principals (including their deny entries),
    integrity levels, the user's rights, and the application's token can affect
    access. Grants through Everyone or a null DACL are not included.

    Does not descend into directory reparse points encountered beneath a root,
    avoiding junction/symlink loops and network targets. Local mounted volumes
    are scanned separately in the default scan. Explicit -Path roots are scanned
    even if they are reparse points; their targets must be trusted.

    Hidden/system folders are included. Read/enumeration failures produce errors
    and a final incomplete-scan warning. Elevation can reduce access failures,
    but does not guarantee every folder can be inspected. No ownership,
    permissions, or privileges are changed.

.PARAMETER Path
    Literal filesystem directories to scan recursively. Defaults to local volumes.
    When specifying paths, separately include any mounted volumes beneath them.

.PARAMETER ExplicitOnly
    Excludes inherited entries, useful for locating where permissions originate.
    All directories are still visited to find explicit entries below them.
    Cannot be combined with -Summary.

.PARAMETER Summary
    Reports maximal fully inspected directory trees with identical applicable
    rights for the selected package group instead of reporting individual ACEs.

.PARAMETER Principal
    Group to inspect with -Summary. Defaults to ALL_APPLICATION_PACKAGES.

.PARAMETER NoRecurse
    Inspects only the specified roots, without enumerating their subdirectories.

.PARAMETER IgnoreEmpty
    With -Summary, omits confirmed empty directories from output and subtree
    comparisons. Such directories can still have different ACLs.

.EXAMPLE
    .\scripts\get-app-package-folder-access.ps1 |
        Export-Csv -LiteralPath .\app-package-folder-access.csv -NoTypeInformation -Encoding UTF8

.EXAMPLE
    .\scripts\get-app-package-folder-access.ps1 -Path 'C:\Program Files', 'D:\Data' |
        Where-Object { $_.AccessControlType -eq 'Allow' -and $_.AppliesToFolder } |
        Format-Table Path, Principal, Rights, IsInherited -AutoSize

.EXAMPLE
    .\scripts\get-app-package-folder-access.ps1 -ExplicitOnly -Verbose

.EXAMPLE
    .\scripts\get-app-package-folder-access.ps1 -Path C:\Windows -Summary |
        Export-Csv -LiteralPath .\app-package-summary.csv -NoTypeInformation -Encoding UTF8

.EXAMPLE
    .\scripts\get-app-package-folder-access.ps1 -Path C:\Windows -Summary `
        -Principal ALL_RESTRICTED_APPLICATION_PACKAGES

.EXAMPLE
    .\scripts\get-app-package-folder-access.ps1 -Path C:\Windows\WinSxS -Summary -IgnoreEmpty
#>

[CmdletBinding(DefaultParameterSetName = 'Detailed')]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path,

    [Parameter(ParameterSetName = 'Detailed')]
    [switch]$ExplicitOnly,

    [Parameter(Mandatory = $true, ParameterSetName = 'Summary')]
    [switch]$Summary,

    [Parameter(ParameterSetName = 'Summary')]
    [ValidateSet('ALL_APPLICATION_PACKAGES', 'ALL_RESTRICTED_APPLICATION_PACKAGES')]
    [string]$Principal = 'ALL_APPLICATION_PACKAGES',

    [switch]$NoRecurse,

    [Parameter(ParameterSetName = 'Summary')]
    [switch]$IgnoreEmpty
)

Set-StrictMode -Version 2.0

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This script requires Windows.'
}

$principals = @{
    'S-1-15-2-1' = 'ALL_APPLICATION_PACKAGES'
    'S-1-15-2-2' = 'ALL_RESTRICTED_APPLICATION_PACKAGES'
}

$summarySid = if ($Principal -eq 'ALL_APPLICATION_PACKAGES') { 'S-1-15-2-1' } else { 'S-1-15-2-2' }

function ConvertTo-DirectoryRightsMask {
    param([long]$Mask)

    $rights = $Mask -band 268435455L
    # FileSystemRights does not name the four generic access bits.
    if ($Mask -band 2147483648L) { $rights = $rights -bor 1179785L }
    if ($Mask -band 1073741824L) { $rights = $rights -bor 1179926L }
    if ($Mask -band 536870912L) { $rights = $rights -bor 1179808L }
    if ($Mask -band 268435456L) { $rights = $rights -bor 2032127L }
    $rights
}

function New-ScanFrame {
    param([IO.DirectoryInfo]$Directory, $Parent)

    [pscustomobject]@{
        Directory               = $Directory
        Parent                  = $Parent
        Ready                   = $false
        AclKnown                = $false
        Uniform                 = $true
        Allowed                 = 0L
        Denied                  = 0L
        Count                   = 1
        IgnoredEmptyFolderCount = 0
        Rows                    = [Collections.Generic.List[object]]::new()
    }
}

function New-FolderAccessSummary {
    param(
        [string]$DirectoryPath,
        [string]$Scope,
        [long]$Allowed = 0,
        [long]$Denied = 0,
        [int]$Count = 0,
        [int]$IgnoredEmptyFolderCount = 0,
        [string]$Note
    )

    $known = $Scope -ne 'Unknown'
    if ($IgnoredEmptyFolderCount -gt 0) {
        $Note = "Excludes $IgnoredEmptyFolderCount confirmed empty directories and their permissions."
    }
    [pscustomobject][ordered]@{
        Path                    = $DirectoryPath
        Principal               = $Principal
        SID                     = $summarySid
        Scope                   = $Scope
        Rights                  = if (-not $known) { $null } elseif ($Allowed) {
            ([Security.AccessControl.FileSystemRights]$Allowed).ToString()
        } else { 'None' }
        AccessMask              = if ($known) { '0x{0:X8}' -f $Allowed } else { $null }
        DeniedRights            = if (-not $known) { $null } elseif ($Denied) {
            ([Security.AccessControl.FileSystemRights]$Denied).ToString()
        } else { 'None' }
        DeniedAccessMask        = if ($known) { '0x{0:X8}' -f $Denied } else { $null }
        FolderCount             = if ($known) { $Count } else { $null }
        IgnoredEmptyFolderCount = if ($known) { $IgnoredEmptyFolderCount } else { $null }
        Note                    = $Note
    }
}

if (-not $PSBoundParameters.ContainsKey('Path')) {
    try {
        $volumes = @(Get-CimInstance -ClassName Win32_Volume -Filter (
            '(DriveType = 2 OR DriveType = 3 OR DriveType = 5 OR DriveType = 6) ' +
            'AND FileSystem IS NOT NULL'
        ) -ErrorAction Stop)
    }
    catch {
        throw "Cannot discover local volumes. Specify -Path to select directories. $($_.Exception.Message)"
    }

    $Path = @(
        foreach ($volume in $volumes) {
            if ($volume.DriveLetter) {
                $volume.DriveLetter + '\'
            }
            elseif ($volume.Name) {
                $volume.Name
            }
            else {
                $volume.DeviceID
            }
        }
    )
    if ($Path.Count -eq 0) {
        throw 'No formatted local volumes were found. Specify -Path to select directories.'
    }
}

$roots = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$pending = [Collections.Generic.Stack[object]]::new()
$failureCount = 0
$folderCount = 0
$entryCount = 0
$skippedReparsePoints = 0
$ignoredEmptyFolders = 0

foreach ($root in $Path) {
    try {
        $item = Get-Item -LiteralPath $root -Force -ErrorAction Stop
        if ($item -isnot [IO.DirectoryInfo]) {
            throw "'$root' is not a filesystem directory."
        }
        if ($roots.Add($item.FullName.TrimEnd([IO.Path]::DirectorySeparatorChar))) {
            $pending.Push((New-ScanFrame -Directory $item))
        }
    }
    catch {
        $failureCount++
        Write-Error -Message "Cannot open scan root '$root': $($_.Exception.Message)" `
            -Category ReadError -TargetObject $root
        if ($Summary) {
            New-FolderAccessSummary -DirectoryPath $root -Scope Unknown -Note 'Cannot open scan root.'
        }
    }
}

try {
    while ($pending.Count -gt 0) {
        $frame = $pending.Pop()
        $directory = $frame.Directory
        if ($frame.Ready) {
            if ($frame.Uniform) {
                $frame.Rows.Clear()
                if ($frame.Allowed) {
                    $frame.Rows.Add((New-FolderAccessSummary -DirectoryPath $directory.FullName `
                        -Scope Subtree -Allowed $frame.Allowed -Denied $frame.Denied -Count $frame.Count `
                        -IgnoredEmptyFolderCount $frame.IgnoredEmptyFolderCount))
                }
            }
            elseif ($frame.AclKnown -and ($frame.Allowed -or $NoRecurse)) {
                $frame.Rows.Insert(0, (New-FolderAccessSummary -DirectoryPath $directory.FullName `
                    -Scope ThisFolder -Allowed $frame.Allowed -Denied $frame.Denied -Count 1))
            }

            if ($null -ne $frame.Parent) {
                $frame.Parent.Count += $frame.Count
                $frame.Parent.IgnoredEmptyFolderCount += $frame.IgnoredEmptyFolderCount
                if (-not $frame.Uniform -or $frame.Allowed -ne $frame.Parent.Allowed -or
                    $frame.Denied -ne $frame.Parent.Denied) {
                    $frame.Parent.Uniform = $false
                }
                $frame.Parent.Rows.AddRange($frame.Rows)
            }
            else {
                foreach ($row in $frame.Rows) {
                    $row
                }
            }
            continue
        }

        $folderCount++
        if ($folderCount % 250 -eq 0) {
            Write-Progress -Activity 'Inspecting application-package folder permissions' `
                -Status "$folderCount folders; $entryCount matching entries; $failureCount errors" `
                -CurrentOperation $directory.FullName
        }

        $emptyCheckFailed = $false
        if ($IgnoreEmpty) {
            try {
                $firstEntry = @(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop |
                    Select-Object -First 1)
                if ($firstEntry.Count -eq 0) {
                    $ignoredEmptyFolders++
                    if ($null -ne $frame.Parent) {
                        $frame.Parent.IgnoredEmptyFolderCount++
                    }
                    Write-Verbose "Ignoring confirmed empty directory '$($directory.FullName)'."
                    continue
                }
            }
            catch {
                $failureCount++
                Write-Error -Message "Cannot inspect contents of '$($directory.FullName)': $($_.Exception.Message)" `
                    -Category ReadError -TargetObject $directory.FullName
                $emptyCheckFailed = $true
                $frame.Uniform = $false
                $frame.Rows.Add((New-FolderAccessSummary -DirectoryPath $directory.FullName `
                    -Scope Unknown -Note 'Cannot determine whether this directory is empty or inspect its subfolders.'))
            }
        }

        try {
            $acl = Get-Acl -LiteralPath $directory.FullName -ErrorAction Stop
            $rules = $acl.GetAccessRules(
                $true, (-not $ExplicitOnly), [Security.Principal.SecurityIdentifier]
            )
            $frame.AclKnown = $true
        }
        catch {
            $failureCount++
            Write-Error -Message "Cannot read ACL for '$($directory.FullName)': $($_.Exception.Message)" `
                -Category ReadError -TargetObject $directory.FullName
            $rules = @()
            $frame.Uniform = $false
            if ($Summary) {
                $frame.Rows.Add((New-FolderAccessSummary -DirectoryPath $directory.FullName `
                    -Scope Unknown -Note 'Cannot read folder ACL.'))
            }
        }

        foreach ($rule in $rules) {
            $sid = $rule.IdentityReference.Value
            if (-not $principals.ContainsKey($sid) -or ($Summary -and $sid -ne $summarySid)) {
                continue
            }

            $entryCount++
            $mask = [long]$rule.FileSystemRights -band [long][uint32]::MaxValue
            $rights = ConvertTo-DirectoryRightsMask $mask
            $appliesToFolder = -not (
                $rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly
            )
            if ($Summary) {
                if ($appliesToFolder) {
                    # Bits already granted or denied are decided by the earlier ACE.
                    if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny) {
                        $frame.Denied = $frame.Denied -bor ($rights -band (-bnot $frame.Allowed))
                    }
                    else {
                        $frame.Allowed = $frame.Allowed -bor ($rights -band (-bnot $frame.Denied))
                    }
                }
                continue
            }

            [pscustomobject][ordered]@{
                Path              = $directory.FullName
                Principal         = $principals[$sid]
                SID               = $sid
                AccessControlType = $rule.AccessControlType.ToString()
                Rights            = ([Security.AccessControl.FileSystemRights]$rights).ToString()
                AccessMask        = '0x{0:X8}' -f $mask
                IsInherited       = $rule.IsInherited
                AppliesToFolder   = $appliesToFolder
                InheritanceFlags  = $rule.InheritanceFlags.ToString()
                PropagationFlags  = $rule.PropagationFlags.ToString()
            }
        }

        if ($Summary) {
            $frame.Ready = $true
            $pending.Push($frame)
        }
        if ($NoRecurse -or $emptyCheckFailed) {
            $frame.Uniform = $false
            continue
        }
        try {
            Get-ChildItem -LiteralPath $directory.FullName -Directory -Force -ErrorAction Stop |
                ForEach-Object {
                    if ($roots.Contains($_.FullName.TrimEnd([IO.Path]::DirectorySeparatorChar))) {
                        # An overlapping root is already queued separately.
                        $frame.Uniform = $false
                        return
                    }
                    if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                        $skippedReparsePoints++
                        Write-Verbose "Not descending into reparse point '$($_.FullName)'."
                        $frame.Uniform = $false
                        if ($Summary) {
                            $frame.Rows.Add((New-FolderAccessSummary -DirectoryPath $_.FullName `
                                -Scope Unknown -Note 'Directory reparse point was not followed.'))
                        }
                    }
                    else {
                        $parent = if ($Summary) { $frame } else { $null }
                        $pending.Push((New-ScanFrame -Directory $_ -Parent $parent))
                    }
                }
        }
        catch {
            $failureCount++
            Write-Error -Message "Cannot list folders under '$($directory.FullName)': $($_.Exception.Message)" `
                -Category ReadError -TargetObject $directory.FullName
            $frame.Uniform = $false
            if ($Summary) {
                $frame.Rows.Add((New-FolderAccessSummary -DirectoryPath $directory.FullName `
                    -Scope Unknown -Note 'Subfolders could not be fully enumerated.'))
            }
        }
    }
}
finally {
    Write-Progress -Activity 'Inspecting application-package folder permissions' -Completed
    Write-Verbose "Inspected $folderCount folders; found $entryCount matching ACL entries."
    if ($IgnoreEmpty) {
        Write-Verbose "Ignored $ignoredEmptyFolders confirmed empty directories."
    }
    if ($skippedReparsePoints -gt 0) {
        Write-Warning (
            "Did not descend into $skippedReparsePoints directory reparse points. " +
            'Supply any additional trusted targets as separate -Path roots.'
        )
    }
    if ($failureCount -gt 0) {
        Write-Warning "Scan incomplete: $failureCount operations failed. See the error stream for paths and reasons."
    }
}
