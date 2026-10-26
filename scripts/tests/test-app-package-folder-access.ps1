# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$scanner = Join-Path $PSScriptRoot '..\get-app-package-folder-access.ps1'
$gapFinder = Join-Path $PSScriptRoot '..\find-app-package-folder-access-gaps.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ('app-package-acl-test-' + [guid]::NewGuid())
$allPackages = 'S-1-15-2-1'
$restrictedPackages = 'S-1-15-2-2'
$testAcls = @{}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw $Message
    }
}

function Set-TestAcl {
    param([string]$Directory, [string]$Sddl)
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($Sddl)
    $testAcls[$Directory] = $acl
}

function Get-Acl {
    param([string]$LiteralPath, $ErrorAction)
    if (-not $testAcls.ContainsKey($LiteralPath)) {
        throw "No test ACL for '$LiteralPath'."
    }
    $testAcls[$LiteralPath]
}

try {
    [void](New-Item -Path $root -ItemType Directory)
    $child = (New-Item -Path (Join-Path $root 'child') -ItemType Directory).FullName
    $hidden = [IO.Directory]::CreateDirectory((Join-Path $root 'hidden [literal]'))
    $hidden.Attributes = $hidden.Attributes -bor [IO.FileAttributes]::Hidden
    $childrenOnly = (New-Item -Path (Join-Path $root 'children-only') -ItemType Directory).FullName
    $descendant = (New-Item -Path (Join-Path $childrenOnly 'descendant') -ItemType Directory).FullName
    $generic = (New-Item -Path (Join-Path $root 'generic-rights') -ItemType Directory).FullName
    $genericRead = (New-Item -Path (Join-Path $root 'generic-read') -ItemType Directory).FullName

    # Real ACL objects, but no changes to filesystem permissions or privileges.
    $inherited = "(A;CIID;0x1200a9;;;$allPackages)"
    Set-TestAcl $root "D:(A;CI;0x1200a9;;;$allPackages)"
    Set-TestAcl $child (
        "D:(D;;0x10000;;;$restrictedPackages)" +
        "(A;;0x120116;;;$restrictedPackages)$inherited"
    )
    Set-TestAcl $hidden.FullName "D:$inherited"
    Set-TestAcl $childrenOnly "D:(A;CIIO;0x120089;;;$restrictedPackages)$inherited"
    Set-TestAcl $descendant "D:$inherited(A;CIID;0x120089;;;$restrictedPackages)"
    Set-TestAcl $generic "D:(A;;0x10000000;;;$restrictedPackages)$inherited"
    Set-TestAcl $genericRead "D:(A;;0x80000000;;;$restrictedPackages)$inherited"

    $rows = @(& $scanner -Path $root -ErrorAction Stop)
    Assert-True (@($rows | Where-Object {
        $_.Path -eq $root -and $_.SID -eq $allPackages -and
        -not $_.IsInherited -and $_.AppliesToFolder -and
        $_.Rights -match 'ReadAndExecute'
    }).Count -eq 1) 'The explicit root grant was not reported.'
    Assert-True (@($rows | Where-Object {
        $_.Path -eq $child -and $_.SID -eq $allPackages -and $_.IsInherited
    }).Count -eq 1) 'The inherited grant was not reported.'
    Assert-True (@($rows | Where-Object {
        $_.Path -eq $child -and $_.Principal -eq 'ALL_RESTRICTED_APPLICATION_PACKAGES' -and
        $_.AccessControlType -eq 'Allow' -and $_.Rights -match 'Write'
    }).Count -eq 1) 'The restricted-packages write grant was not reported.'
    Assert-True (@($rows | Where-Object {
        $_.Path -eq $child -and $_.SID -eq $restrictedPackages -and
        $_.AccessControlType -eq 'Deny' -and $_.Rights -eq 'Delete'
    }).Count -eq 1) 'The deny entry was not reported separately.'
    Assert-True (@($rows | Where-Object {
        $_.Path -eq $childrenOnly -and $_.SID -eq $restrictedPackages -and
        -not $_.AppliesToFolder
    }).Count -eq 1) 'An inherit-only entry was incorrectly reported as applying to its folder.'
    Assert-True (@($rows | Where-Object {
        $_.Path -eq $descendant -and $_.SID -eq $restrictedPackages -and
        $_.AppliesToFolder -and $_.IsInherited
    }).Count -eq 1) 'The child did not receive its inherited grant.'
    Assert-True (@($rows | Where-Object {
        $_.Path -eq $generic -and $_.SID -eq $restrictedPackages -and
        $_.Rights -eq 'FullControl' -and $_.AccessMask -eq '0x10000000'
    }).Count -eq 1) 'Generic access rights were not decoded or preserved correctly.'
    Assert-True (@($rows | Where-Object {
        $_.Path -eq $genericRead -and $_.SID -eq $restrictedPackages -and
        $_.Rights -eq 'Read, Synchronize' -and $_.AccessMask -eq '0x80000000'
    }).Count -eq 1) 'A signed generic-read mask was not decoded correctly.'
    Assert-True (@($rows | Where-Object { $_.Path -eq $hidden.FullName }).Count -eq 1) `
        'A hidden directory containing wildcard characters was skipped.'

    $literalRows = @(& $scanner -Path $hidden.FullName -ErrorAction Stop)
    Assert-True ($literalRows.Count -eq 1) 'A literal scan root was treated as a wildcard.'
    $explicitRows = @(& $scanner -Path $root -ExplicitOnly -ErrorAction Stop)
    Assert-True (@($explicitRows | Where-Object IsInherited).Count -eq 0) `
        'ExplicitOnly returned inherited entries.'
    Assert-True (@($explicitRows | Where-Object { $_.Path -eq $child }).Count -eq 2) `
        'ExplicitOnly failed to inspect descendants.'
    $overlappingRows = @(& $scanner -Path $root, $child, ($root + '\'), ($child + '\') -ErrorAction Stop)
    Assert-True ($overlappingRows.Count -eq $rows.Count) 'Overlapping roots duplicated results.'
    $csvRows = @($rows | ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv)
    Assert-True ($csvRows.Count -eq $rows.Count -and $csvRows[0].Path -eq $rows[0].Path) `
        'Scanner output did not round-trip through CSV.'

    $summaryRows = @(& $scanner -Path $root -Summary -ErrorAction Stop)
    Assert-True ($summaryRows.Count -eq 1 -and $summaryRows[0].Path -eq $root -and
        $summaryRows[0].Scope -eq 'Subtree' -and
        $summaryRows[0].Principal -eq 'ALL_APPLICATION_PACKAGES' -and
        $summaryRows[0].AccessMask -eq '0x001200A9' -and
        $summaryRows[0].FolderCount -eq @($rows.Path | Sort-Object -Unique).Count) `
        'A uniform tree with explicit and inherited grants did not collapse to its root.'
    $summaryCsv = @($summaryRows | ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv)
    Assert-True ($summaryCsv.Count -eq 1 -and $summaryCsv[0].Scope -eq 'Subtree') `
        'Summary output did not round-trip through CSV.'
    $overlappingSummary = @(& $scanner -Path $root, $child, ($root + '\') -Summary -ErrorAction Stop)
    Assert-True (@($overlappingSummary | Where-Object {
        $_.Path -eq $root -and $_.Scope -eq 'Subtree'
    }).Count -eq 0 -and
        @($overlappingSummary.Path | Sort-Object -Unique).Count -eq $overlappingSummary.Count -and
        ($overlappingSummary | Measure-Object FolderCount -Sum).Sum -eq $summaryRows[0].FolderCount) `
        'Overlapping summary roots duplicated coverage or hid a separately scanned branch.'

    $restrictedRows = @(& $scanner -Path $root -Summary `
        -Principal ALL_RESTRICTED_APPLICATION_PACKAGES -ErrorAction Stop)
    Assert-True ($restrictedRows.Count -gt 0 -and
        @($restrictedRows | Where-Object { $_.Principal -ne 'ALL_RESTRICTED_APPLICATION_PACKAGES' }).Count -eq 0 -and
        @($restrictedRows | Where-Object { $_.Path -eq $root }).Count -eq 0) `
        'The restricted-package summary included grants for the other group.'
    Assert-True (@($restrictedRows | Where-Object {
        $_.Path -eq $child -and $_.Rights -match 'Write' -and $_.DeniedRights -eq 'Delete'
    }).Count -eq 1) 'The restricted-package summary lost its separate allow and deny rights.'
    Assert-True (@($restrictedRows | Where-Object { $_.Path -eq $childrenOnly }).Count -eq 0 -and
        @($restrictedRows | Where-Object { $_.Path -eq $descendant }).Count -eq 1) `
        'An inherit-only ACE was treated as a grant on its folder.'

    $rejected = $false
    try {
        [void](& $scanner -Path $root -Summary -ExplicitOnly -ErrorAction Stop)
    }
    catch [Management.Automation.ParameterBindingException] {
        $rejected = $true
    }
    Assert-True $rejected 'Summary allowed inherited ACEs to be excluded from its access calculation.'

    # Isolate discovery from host CIM permissions; exercise the default entry point.
    function Get-CimInstance {
        param($ClassName, $Filter, $ErrorAction)
        Assert-True ($ClassName -eq 'Win32_Volume') 'Unexpected volume-discovery class.'
        [pscustomobject]@{ DriveLetter = $null; Name = $root; DeviceID = 'unused' }
    }
    $defaultRows = @(& $scanner -ErrorAction Stop)
    Assert-True ($defaultRows.Count -eq $rows.Count) 'Default volume discovery missed a mounted root.'
    $defaultSummary = @(& $scanner -Summary -ErrorAction Stop)
    Assert-True ($defaultSummary.Count -eq 1 -and
        $defaultSummary[0].FolderCount -eq $summaryRows[0].FolderCount) `
        'Summary mode did not scan the discovered volume root.'
    Remove-Item Function:\Get-CimInstance

    $scanErrors = @()
    $scanWarnings = @()
    $rootAcl = $testAcls[$root]
    $testAcls.Remove($root)
    $partialRows = @(& $scanner -Path $root -ErrorAction Continue `
        -ErrorVariable +scanErrors -WarningVariable +scanWarnings 2>$null 3>$null)
    $partialSummary = @(& $scanner -Path $root -Summary -ErrorAction Continue 2>$null 3>$null)
    $testAcls[$root] = $rootAcl
    Assert-True ($partialRows.Count -eq ($rows.Count - 1) -and $scanErrors.Count -gt 0) `
        'An ACL-read failure prevented inspection of accessible descendants.'
    Assert-True (@($scanWarnings | Where-Object { "$_" -like 'Scan incomplete:*' }).Count -eq 1) `
        'An ACL-read failure did not produce a summary warning.'
    Assert-True (@($partialSummary | Where-Object {
        $_.Path -eq $root -and $_.Scope -eq 'Unknown' -and $null -eq $_.Rights
    }).Count -eq 1 -and @($partialSummary | Where-Object {
        $_.Path -eq $root -and $_.Scope -eq 'Subtree'
    }).Count -eq 0) 'An unreadable ACL was incorrectly covered by a collapsed access grant.'
    Assert-True (@($partialSummary | Where-Object {
        $_.Path -eq $child -and $_.Scope -eq 'Subtree'
    }).Count -eq 1) 'An unreadable parent prevented reporting an accessible child subtree.'

    function Get-ChildItem {
        param([string]$LiteralPath, [switch]$Directory, [switch]$Force, $ErrorAction)
        if ($LiteralPath -eq $childrenOnly) {
            throw 'Simulated enumeration failure.'
        }
        Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
        if ($LiteralPath -eq $root) {
            [pscustomobject]@{
                FullName   = Join-Path $root 'simulated-junction'
                Attributes = [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint
            }
        }
    }
    $scanErrors = @()
    $scanWarnings = @()
    $partialRows = @(& $scanner -Path $root -ErrorAction Continue `
        -ErrorVariable +scanErrors -WarningVariable +scanWarnings 2>$null 3>$null)
    Assert-True (@($partialRows | Where-Object { $_.Path -eq $descendant }).Count -eq 0) `
        'The enumeration-failure fixture was not exercised.'
    Assert-True (@($partialRows | Where-Object { $_.Path -eq $child }).Count -eq 3) `
        'An enumeration failure prevented inspection of sibling directories.'
    Assert-True (@($scanErrors | Where-Object {
        "$_" -like '*Cannot list folders under*'
    }).Count -gt 0) 'An enumeration failure did not produce an error.'
    Assert-True (@($scanErrors | Where-Object {
        "$_" -like '*simulated-junction*'
    }).Count -eq 0) 'The scanner followed a reparse point.'
    Assert-True (@($scanWarnings | Where-Object {
        "$_" -like '*1 directory reparse points*'
    }).Count -eq 1) 'Skipped reparse points were not disclosed.'
    $partialSummary = @(& $scanner -Path $root -Summary -ErrorAction Continue 2>$null 3>$null)
    Assert-True (@($partialSummary | Where-Object {
        $_.Path -eq $root -and $_.Scope -eq 'Subtree'
    }).Count -eq 0) 'A partially enumerated subtree was collapsed.'
    Assert-True (@($partialSummary | Where-Object {
        $_.Path -eq $childrenOnly -and $_.Scope -eq 'Unknown'
    }).Count -eq 1 -and @($partialSummary | Where-Object {
        $_.Path -eq (Join-Path $root 'simulated-junction') -and $_.Scope -eq 'Unknown'
    }).Count -eq 1) 'Enumeration failures and skipped reparse points were not represented as unknown.'
    Remove-Item Function:\Get-ChildItem

    $scanErrors = @()
    $scanWarnings = @()
    $missingRows = @(& $scanner -Path (Join-Path $root 'missing') `
        -ErrorAction Continue -ErrorVariable +scanErrors -WarningVariable +scanWarnings 2>$null 3>$null)
    Assert-True ($missingRows.Count -eq 0 -and $scanErrors.Count -gt 0) `
        'An unreadable root did not produce an error.'
    Assert-True (@($scanWarnings | Where-Object { "$_" -like 'Scan incomplete:*' }).Count -eq 1) `
        'An incomplete scan did not produce a summary warning.'
    $missingSummary = @(& $scanner -Path (Join-Path $root 'missing') -Summary `
        -ErrorAction Continue 2>$null 3>$null)
    Assert-True ($missingSummary.Count -eq 1 -and $missingSummary[0].Scope -eq 'Unknown' -and
        $null -eq $missingSummary[0].Rights) 'An unreadable scan root was not represented as unknown.'

    $caseRoot = (New-Item -Path (Join-Path $root 'summary-cases') -ItemType Directory).FullName
    $same = (New-Item -Path (Join-Path $caseRoot 'same') -ItemType Directory).FullName
    $sameChild = (New-Item -Path (Join-Path $same 'child') -ItemType Directory).FullName
    $noGrant = (New-Item -Path (Join-Path $caseRoot 'no-grant') -ItemType Directory).FullName
    $readableChild = (New-Item -Path (Join-Path $noGrant 'readable') -ItemType Directory).FullName
    $different = (New-Item -Path (Join-Path $caseRoot 'different-rights') -ItemType Directory).FullName
    $denied = (New-Item -Path (Join-Path $caseRoot 'denied') -ItemType Directory).FullName
    $inheritOnly = (New-Item -Path (Join-Path $caseRoot 'inherit-only') -ItemType Directory).FullName
    $inheritedChild = (New-Item -Path (Join-Path $inheritOnly 'child') -ItemType Directory).FullName
    $split = (New-Item -Path (Join-Path $caseRoot 'split-grants') -ItemType Directory).FullName
    $ordered = (New-Item -Path (Join-Path $caseRoot 'ordered-deny') -ItemType Directory).FullName

    Set-TestAcl $caseRoot "D:P(A;;0x1200a9;;;$allPackages)"
    Set-TestAcl $same "D:P(A;;GXGR;;;$allPackages)"
    Set-TestAcl $sameChild "D:P(A;;0x1200a9;;;$allPackages)"
    Set-TestAcl $noGrant 'D:P'
    Set-TestAcl $readableChild "D:P(A;;GXGR;;;$allPackages)"
    Set-TestAcl $different "D:P(A;;0x1301bf;;;$allPackages)"
    Set-TestAcl $denied "D:P(D;;GXGR;;;$allPackages)(A;;GXGR;;;$allPackages)"
    Set-TestAcl $inheritOnly "D:P(A;OICIIO;GXGR;;;$allPackages)"
    Set-TestAcl $inheritedChild "D:(A;ID;GXGR;;;$allPackages)"
    Set-TestAcl $split "D:P(A;;GR;;;$allPackages)(A;;GX;;;$allPackages)"
    Set-TestAcl $ordered "D:(A;;GR;;;$allPackages)(D;ID;GR;;;$allPackages)"

    $mixedSummary = @(& $scanner -Path $caseRoot -Summary -ErrorAction Stop)
    Assert-True ($mixedSummary.Count -eq 7) 'The mixed-access tree produced an unexpected set of summaries.'
    Assert-True (@($mixedSummary | Where-Object {
        $_.Path -eq $caseRoot -and $_.Scope -eq 'ThisFolder' -and $_.FolderCount -eq 1
    }).Count -eq 1) 'A parent grant was incorrectly used to cover inaccessible or different-rights descendants.'
    Assert-True (@($mixedSummary | Where-Object {
        $_.Path -eq $same -and $_.Scope -eq 'Subtree' -and $_.FolderCount -eq 2 -and
        $_.AccessMask -eq '0x001200A9'
    }).Count -eq 1 -and @($mixedSummary | Where-Object { $_.Path -eq $sameChild }).Count -eq 0) `
        'Protected explicit copies of equivalent generic and specific rights did not collapse.'
    Assert-True (@($mixedSummary | Where-Object { $_.Path -in @($noGrant, $denied, $inheritOnly) }).Count -eq 0 -and
        @($mixedSummary | Where-Object { $_.Path -in @($readableChild, $inheritedChild) }).Count -eq 2) `
        'Missing grants, deny ACEs, or inherit-only ACEs hid accessible descendants or created false grants.'
    Assert-True (@($mixedSummary | Where-Object {
        $_.Path -eq $different -and $_.AccessMask -eq '0x001301BF'
    }).Count -eq 1) 'Different descendant rights were not preserved.'
    Assert-True (@($mixedSummary | Where-Object {
        $_.Path -eq $split -and $_.AccessMask -eq '0x001200A9'
    }).Count -eq 1) 'Multiple applicable allow ACEs were not combined.'
    Assert-True (@($mixedSummary | Where-Object {
        $_.Path -eq $ordered -and $_.AccessMask -eq '0x00120089' -and $_.DeniedRights -eq 'None'
    }).Count -eq 1) 'An inherited deny incorrectly overrode rights already decided by an explicit allow.'
    $otherGroupSummary = @(& $scanner -Path $caseRoot -Summary `
        -Principal ALL_RESTRICTED_APPLICATION_PACKAGES -ErrorAction Stop)
    Assert-True ($otherGroupSummary.Count -eq 0) 'The summary combined rights across package groups.'

    $oneLevel = @(& $scanner -Path $caseRoot, $noGrant -Summary -NoRecurse -ErrorAction Stop)
    Assert-True ($oneLevel.Count -eq 2 -and
        @($oneLevel | Where-Object { $_.Scope -ne 'ThisFolder' -or $_.FolderCount -ne 1 }).Count -eq 0 -and
        @($oneLevel | Where-Object {
            $_.Path -eq $noGrant -and $_.Rights -eq 'None' -and $_.AccessMask -eq '0x00000000'
        }).Count -eq 1) 'A nonrecursive summary omitted a known zero-rights result or claimed descendant coverage.'
    $oneLevelDetails = @(& $scanner -Path $caseRoot -NoRecurse -ErrorAction Stop)
    Assert-True ($oneLevelDetails.Count -eq 1 -and $oneLevelDetails[0].Path -eq $caseRoot) `
        'The detailed nonrecursive scan visited descendants.'

    $noGrantItem = Get-Item -LiteralPath $noGrant -Force
    $noGrantItem.Attributes = $noGrantItem.Attributes -bor [IO.FileAttributes]::Hidden
    $descendantAcl = $testAcls[$readableChild]
    $testAcls.Remove($readableChild)
    $gaps = @(& $gapFinder -Path $caseRoot -ErrorAction Stop)
    $testAcls[$readableChild] = $descendantAcl
    Assert-True ($gaps.Count -eq 3 -and
        @($gaps | Where-Object {
            $_.Path -notin @($noGrant, $denied, $inheritOnly) -or $_.Status -ne 'NoApplicableGrant'
        }).Count -eq 0) `
        'The gap finder skipped a hidden missing grant, ignored a deny, counted inherit-only rights, or recursed.'
    $regularGaps = @(& $gapFinder -Path $same -ErrorAction Stop)
    Assert-True ($regularGaps.Count -eq 0) 'A folder with an applicable grant was reported as a gap.'
    $restrictedGaps = @(& $gapFinder -Path $same `
        -Principal ALL_RESTRICTED_APPLICATION_PACKAGES -ErrorAction Stop)
    Assert-True ($restrictedGaps.Count -eq 1 -and $restrictedGaps[0].Path -eq $sameChild -and
        $restrictedGaps[0].Status -eq 'NoApplicableGrant') `
        'The gap finder used the wrong package group.'

    $noGrantAcl = $testAcls[$noGrant]
    $testAcls.Remove($noGrant)
    function Get-ChildItem {
        param([string]$LiteralPath, [switch]$Directory, [switch]$Force, $ErrorAction)
        Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
        [pscustomobject]@{
            FullName   = Join-Path $LiteralPath 'simulated-junction'
            Attributes = [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint
        }
    }
    $unknownGaps = @(& $gapFinder -Path $caseRoot -ErrorAction Continue 2>$null 3>$null)
    Remove-Item Function:\Get-ChildItem
    $testAcls[$noGrant] = $noGrantAcl
    Assert-True (@($unknownGaps | Where-Object {
        $_.Path -eq $noGrant -and $_.Status -eq 'Unknown'
    }).Count -eq 1 -and @($unknownGaps | Where-Object {
        $_.Path -eq (Join-Path $caseRoot 'simulated-junction') -and $_.Status -eq 'Unknown'
    }).Count -eq 1 -and @($unknownGaps | Where-Object {
        $_.Status -eq 'NoApplicableGrant'
    }).Count -eq 2) 'Unreadable ACLs or skipped links were incorrectly reported as missing grants.'

    $emptyRoot = (New-Item -Path (Join-Path $root 'empty-cases') -ItemType Directory).FullName
    $content = (New-Item -Path (Join-Path $emptyRoot 'content') -ItemType Directory).FullName
    $hiddenContent = (New-Item -Path (Join-Path $emptyRoot 'hidden-content') -ItemType Directory).FullName
    $emptyAllowed = (New-Item -Path (Join-Path $emptyRoot 'empty-allowed') -ItemType Directory).FullName
    $emptyDenied = (New-Item -Path (Join-Path $emptyRoot 'empty-denied') -ItemType Directory).FullName
    $branch = (New-Item -Path (Join-Path $emptyRoot 'branch') -ItemType Directory).FullName
    $emptyChild = (New-Item -Path (Join-Path $branch 'empty-child') -ItemType Directory).FullName
    [void](New-Item -Path (Join-Path $content 'zero-length.txt') -ItemType File)
    $hiddenEntry = New-Item -Path (Join-Path $hiddenContent 'hidden.txt') -ItemType File
    $hiddenEntry.Attributes = $hiddenEntry.Attributes -bor [IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System
    foreach ($directory in @($emptyRoot, $content, $hiddenContent, $emptyAllowed, $branch)) {
        Set-TestAcl $directory "D:P(A;;GXGR;;;$allPackages)"
    }
    Set-TestAcl $emptyDenied 'D:P'
    Set-TestAcl $emptyChild 'D:P'

    $unfiltered = @(& $scanner -Path $emptyRoot -Summary -ErrorAction Stop)
    Assert-True (@($unfiltered | Where-Object {
        $_.Path -eq $emptyRoot -and $_.Scope -eq 'ThisFolder'
    }).Count -eq 1) 'Empty folders were ignored without the opt-in flag.'

    $filtered = @(& $scanner -Path $emptyRoot -Summary -IgnoreEmpty -ErrorAction Stop)
    Assert-True ($filtered.Count -eq 1 -and $filtered[0].Path -eq $emptyRoot -and
        $filtered[0].Scope -eq 'Subtree' -and $filtered[0].FolderCount -eq 4 -and
        $filtered[0].IgnoredEmptyFolderCount -eq 3 -and $filtered[0].Note -like '*Excludes 3*') `
        'Ignoring empty directories did not collapse the non-empty tree or disclose the excluded permissions.'
    $emptyOnly = @(& $scanner -Path $emptyDenied -Summary -IgnoreEmpty -ErrorAction Stop)
    Assert-True ($emptyOnly.Count -eq 0) 'A confirmed empty scan root was not ignored.'
    $filteredOneLevel = @(& $scanner -Path $content -Summary -IgnoreEmpty -NoRecurse -ErrorAction Stop)
    Assert-True ($filteredOneLevel.Count -eq 1 -and $filteredOneLevel[0].Scope -eq 'ThisFolder') `
        'Ignoring empty directories made a nonrecursive result claim descendant coverage.'

    $contentAcl = $testAcls[$content]
    $testAcls.Remove($content)
    $unknownContents = @(& $scanner -Path $emptyRoot -Summary -IgnoreEmpty `
        -ErrorAction Continue 2>$null 3>$null)
    $testAcls[$content] = $contentAcl
    Assert-True (@($unknownContents | Where-Object {
        $_.Path -eq $content -and $_.Scope -eq 'Unknown'
    }).Count -eq 1 -and @($unknownContents | Where-Object {
        $_.Path -eq $emptyRoot -and $_.Scope -eq 'Subtree'
    }).Count -eq 0) 'Ignoring empty directories hid a non-empty folder with an unreadable ACL.'

    $uninspectable = (New-Item -Path (Join-Path $emptyRoot 'uninspectable') -ItemType Directory).FullName
    Set-TestAcl $uninspectable "D:P(A;;GXGR;;;$allPackages)"
    $inspectionAttempts = [Collections.Generic.List[string]]::new()
    function Get-ChildItem {
        param([string]$LiteralPath, [switch]$Directory, [switch]$Force, $ErrorAction)
        if ($LiteralPath -eq $uninspectable) {
            $inspectionAttempts.Add($LiteralPath)
            throw 'Simulated content-enumeration failure.'
        }
        Microsoft.PowerShell.Management\Get-ChildItem @PSBoundParameters
        if ($LiteralPath -eq $emptyRoot -and $Directory) {
            [pscustomobject]@{
                FullName   = Join-Path $LiteralPath 'simulated-junction'
                Attributes = [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReparsePoint
            }
        }
    }
    $unknownContents = @(& $scanner -Path $emptyRoot -Summary -IgnoreEmpty `
        -ErrorAction Continue 2>$null 3>$null)
    Remove-Item Function:\Get-ChildItem
    Assert-True ($inspectionAttempts.Count -eq 1 -and @($unknownContents | Where-Object {
        $_.Path -eq $uninspectable -and $_.Scope -eq 'Unknown'
    }).Count -eq 1 -and @($unknownContents | Where-Object {
        $_.Path -eq (Join-Path $emptyRoot 'simulated-junction') -and $_.Scope -eq 'Unknown'
    }).Count -eq 1 -and @($unknownContents | Where-Object {
        $_.Path -eq $emptyRoot -and $_.Scope -eq 'Subtree'
    }).Count -eq 0) 'Unreadable contents or skipped reparse points were incorrectly treated as empty.'

    Write-Host 'Application-package folder permission checks passed.'
}
finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
