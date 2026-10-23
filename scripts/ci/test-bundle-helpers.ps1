# Helpers shared by the backend test-bundle build scripts. Dot-source this file.

function Invoke-Checked {
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Command
    )

    $global:LASTEXITCODE = 0
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

# Paths come from cargo's report, so any target directory works.
function Invoke-CargoBuild {
    param(
        [Parameter(Mandatory)][string]$SourceRoot,
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    Push-Location $SourceRoot
    try {
        $messages = Invoke-Checked "cargo $($Arguments -join ' ')" {
            cargo @Arguments --locked --release --target $Target --message-format=json
        }
    }
    finally {
        Pop-Location
    }
    $messages | ForEach-Object {
        try { $_ | ConvertFrom-Json -ErrorAction Stop } catch { }
    } | Where-Object { $_.reason -eq 'compiler-artifact' }
}

function Get-CargoExecutable {
    param([object[]]$Artifacts, [string]$TargetName)

    $path = $Artifacts |
        Where-Object { $_.target.name -eq $TargetName -and $_.executable } |
        Select-Object -Last 1 -ExpandProperty executable
    if (-not $path) {
        throw "cargo reported no executable for $TargetName."
    }
    $path
}

function Get-CargoLibrary {
    param([object[]]$Artifacts, [string]$TargetName)

    $path = $Artifacts |
        Where-Object { $_.target.name -eq $TargetName } |
        ForEach-Object { $_.filenames } |
        Where-Object { [IO.Path]::GetExtension($_) -eq '.dll' } |
        Select-Object -Last 1
    if (-not $path) {
        throw "cargo reported no $TargetName.dll."
    }
    $path
}

function New-Directory {
    param([Parameter(Mandatory)][string]$Path)

    (New-Item -ItemType Directory -Force -Path $Path).FullName
}

# Build the Node SDK and its integration suite against the native files in
# $NativeFiles, then stage the named test files, the suite's dependencies, the
# freshly built SDK and this machine's Node runtime into $OutputDirectory.
function Copy-NodeIntegrationSuite {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$Architecture,
        [Parameter(Mandatory)][string[]]$NativeFiles,
        [Parameter(Mandatory)][string[]]$TestFiles,
        [Parameter(Mandatory)][string]$OutputDirectory
    )

    $nodeSdkRoot = Join-Path $RepoRoot 'sdk\node'
    $integrationRoot = Join-Path $nodeSdkRoot 'tests\integration'
    $sdkBin = New-Directory (Join-Path $nodeSdkRoot "bin\$Architecture")
    Copy-Item -LiteralPath $NativeFiles -Destination $sdkBin -Force
    foreach ($project in $nodeSdkRoot, $integrationRoot) {
        Push-Location $project
        try {
            Invoke-Checked "npm ci in $project" { npm ci }
            Invoke-Checked "npm run build in $project" { npm run build }
        }
        finally {
            Pop-Location
        }
    }

    $nodeExe = (Get-Command node -CommandType Application | Select-Object -First 1).Source
    Copy-Item -LiteralPath $nodeExe, (Join-Path (Split-Path -Parent $nodeExe) 'LICENSE') -Destination (New-Directory (Join-Path $OutputDirectory 'node'))

    $integrationOut = New-Directory (Join-Path $OutputDirectory 'sdk-integration')
    $distOut = New-Directory (Join-Path $integrationOut 'dist')
    foreach ($name in @($TestFiles) + 'test-helpers.js') {
        Copy-Item -Path (Join-Path $integrationRoot "dist\$name") -Destination $distOut
    }
    Copy-Item -LiteralPath (Join-Path $integrationRoot 'package.json'), (Join-Path $integrationRoot 'run-tests.js') -Destination $integrationOut

    # Stages the SDK built above in place of the installed copy.
    $modulesOut = New-Directory (Join-Path $integrationOut 'node_modules')
    Get-ChildItem -LiteralPath (Join-Path $integrationRoot 'node_modules') -Force |
        Where-Object Name -ne '@microsoft' |
        Copy-Item -Destination $modulesOut -Recurse -Force
    $sdkOut = New-Directory (Join-Path $modulesOut '@microsoft\mxc-sdk')
    foreach ($name in 'bin', 'dist', 'node_modules', 'package.json', 'LICENSE.md') {
        $source = Join-Path $nodeSdkRoot $name
        if (Test-Path -LiteralPath $source) {
            Copy-Item -LiteralPath $source -Destination $sdkOut -Recurse -Force
        }
    }
}

function Assert-BundleFiles {
    param(
        [Parameter(Mandatory)][string]$OutputDirectory,
        [Parameter(Mandatory)][string[]]$RelativePaths
    )

    foreach ($relativePath in $RelativePaths) {
        if (-not (Test-Path -LiteralPath (Join-Path $OutputDirectory $relativePath) -PathType Leaf)) {
            throw "The bundle is missing $relativePath."
        }
    }
}

function Assert-Discovery {
    param(
        [Parameter(Mandatory)][string]$Payload,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][scriptblock]$Command
    )

    $output = @(Invoke-Checked "Listing the $Payload" $Command)
    $output | ForEach-Object { Write-Host $_ }
    if (($output -join "`n") -notmatch $Pattern) {
        throw "The $Payload discovered no tests."
    }
}
