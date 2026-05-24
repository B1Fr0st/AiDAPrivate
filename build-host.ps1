param(
    [switch]$FullClean,
    [switch]$Drivers,
    [switch]$CleanDrivers,
    [switch]$CleanBuildTree,
    [switch]$Configure,
    [switch]$SkipVerify,
    [switch]$PlanOnly,
    [switch]$NoToast,
    [string]$Preset = "ninja-msvc-release",
    [string]$VsVars = "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildDir = Join-Path $Root "build-ninja"
$RunId = Get-Date -Format "yyyyMMdd-HHmmss"
$LogDir = Join-Path $env:TEMP "aida-build-$RunId"
$SummaryPath = Join-Path $LogDir "summary.json"
$StableSummaryPath = Join-Path $env:TEMP "aida_build_summary.json"
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$Results = New-Object System.Collections.Generic.List[object]

if ($FullClean) {
    $Drivers = $true
    $CleanDrivers = $true
    $CleanBuildTree = $true
    $Configure = $true
}

if (-not (Test-Path -LiteralPath $VsVars)) {
    throw "vcvars64.bat was not found at $VsVars"
}

if ($CleanBuildTree) {
    $Configure = $true
}

if (-not (Test-Path -LiteralPath (Join-Path $BuildDir "build.ninja"))) {
    $Configure = $true
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function New-Step {
    param(
        [string]$Name,
        [string]$Command,
        [string]$LogName,
        [string]$StableLog
    )
    [pscustomobject]@{
        Name = $Name
        Command = $Command
        Log = Join-Path $LogDir $LogName
        StableLog = $StableLog
    }
}

function Invoke-CmdStep {
    param([pscustomobject]$Step)
    $stepWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $started = Get-Date
    Write-Host "[$($started.ToString('HH:mm:ss'))] START $($Step.Name)"
    Write-Host "[$($started.ToString('HH:mm:ss'))] LOG   $($Step.Log)"
    $cmdLine = "call `"$VsVars`" && cd /d `"$Root`" && $($Step.Command)"
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $env:ComSpec /d /s /c $cmdLine *> $Step.Log
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    $stepWatch.Stop()
    if ($Step.StableLog) {
        Copy-Item -LiteralPath $Step.Log -Destination $Step.StableLog -Force
    }
    $finished = Get-Date
    $record = [pscustomobject]@{
        name = $Step.Name
        exit_code = $code
        started = $started.ToString("o")
        finished = $finished.ToString("o")
        elapsed = $stepWatch.Elapsed.ToString()
        log = $Step.Log
        stable_log = $Step.StableLog
    }
    $script:Results.Add($record)
    Write-Host "[$($finished.ToString('HH:mm:ss'))] END   $($Step.Name) exit=$code elapsed=$($stepWatch.Elapsed)"
    if ($code -ne 0) {
        $tail = ""
        if (Test-Path -LiteralPath $Step.Log) {
            $tail = (Get-Content -Tail 80 -LiteralPath $Step.Log) -join [Environment]::NewLine
        }
        throw "$($Step.Name) failed with exit code $code. Log: $($Step.Log)$([Environment]::NewLine)$tail"
    }
}

function Clear-AidaBuildTree {
    $resolvedRoot = [System.IO.Path]::GetFullPath($Root)
    $resolvedBuild = [System.IO.Path]::GetFullPath($BuildDir)
    $rootPrefix = $resolvedRoot.TrimEnd('\') + '\'
    if (-not $resolvedBuild.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove build tree outside repo: $resolvedBuild"
    }
    if ((Split-Path -Leaf $resolvedBuild) -ne "build-ninja") {
        throw "Refusing to remove unexpected build directory: $resolvedBuild"
    }
    if (Test-Path -LiteralPath $resolvedBuild) {
        Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] REMOVE $resolvedBuild"
        Remove-Item -LiteralPath $resolvedBuild -Recurse -Force
    }
}

function Send-AidaBuildNotification {
    param(
        [string]$Status,
        [string]$Message
    )
    try {
        $tone = 1200
        if ($Status -ne "success") {
            $tone = 420
        }
        [Console]::Beep($tone, 350)
    } catch {
    }
    try {
        Write-Host "`a" -NoNewline
    } catch {
    }
    if ($NoToast) {
        return
    }
    try {
        $burntToast = Get-Command New-BurntToastNotification -ErrorAction SilentlyContinue
        if ($burntToast) {
            New-BurntToastNotification -Text "AiDA build $Status", $Message | Out-Null
            return
        }
    } catch {
    }
    try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
        $template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
        $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
        $nodes = $xml.GetElementsByTagName("text")
        [void]$nodes.Item(0).AppendChild($xml.CreateTextNode("AiDA build $Status"))
        [void]$nodes.Item(1).AppendChild($xml.CreateTextNode($Message))
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("AiDA Build").Show($toast)
    } catch {
    }
}

function Write-Summary {
    param(
        [string]$Status,
        [string]$Message,
        [int]$ExitCode
    )
    $Stopwatch.Stop()
    $summary = [ordered]@{
        status = $Status
        message = $Message
        exit_code = $ExitCode
        run_id = $RunId
        repo = $Root
        preset = $Preset
        log_dir = $LogDir
        elapsed = $Stopwatch.Elapsed.ToString()
        clean_build_tree = [bool]$CleanBuildTree
        drivers = [bool]$Drivers
        clean_drivers = [bool]$CleanDrivers
        configure = [bool]$Configure
        verify = -not [bool]$SkipVerify
        steps = $Results
    }
    $json = $summary | ConvertTo-Json -Depth 8
    $json | Set-Content -LiteralPath $SummaryPath -Encoding UTF8
    Copy-Item -LiteralPath $SummaryPath -Destination $StableSummaryPath -Force
    Write-Host "SUMMARY $SummaryPath"
    Write-Host "SUMMARY $StableSummaryPath"
}

$steps = New-Object System.Collections.Generic.List[object]

if ($Drivers) {
    $driverParts = @(
        "if not exist build-ninja\Release mkdir build-ninja\Release",
        "driver\Sentinel\nuget.exe restore driver\Sentinel\Sentinel.sln",
        "driver\Sentinel\nuget.exe restore driver\AiDAShadowFS\AiDAShadowFS.sln",
        "driver\Sentinel\nuget.exe restore driver\WhosWho\WhosWho.sln"
    )
    if ($CleanDrivers) {
        $driverParts += "msbuild driver\WhosWho\WhosWho.sln /t:Clean /p:Configuration=Release /p:Platform=x64 /m /v:minimal"
    }
    $driverParts += "msbuild driver\WhosWho\WhosWho.sln /t:Build /p:Configuration=Release /p:Platform=x64 /m /v:minimal"
    $steps.Add((New-Step "drivers" ($driverParts -join " && ") "driver.log" (Join-Path $env:TEMP "aida_driver_build_out.txt")))
}

if ($Configure) {
    $steps.Add((New-Step "configure" "cmake --preset $Preset" "configure.log" (Join-Path $env:TEMP "aida_configure_out.txt")))
}

$steps.Add((New-Step "build" "cmake --build --preset $Preset" "build.log" (Join-Path $env:TEMP "aida_build_out.txt")))

if (-not $SkipVerify) {
    $steps.Add((New-Step "verify" "cmake --build --preset $Preset" "verify.log" (Join-Path $env:TEMP "aida_build_verify_out.txt")))
}

if ($PlanOnly) {
    [pscustomobject]@{
        run_id = $RunId
        repo = $Root
        preset = $Preset
        clean_build_tree = [bool]$CleanBuildTree
        drivers = [bool]$Drivers
        clean_drivers = [bool]$CleanDrivers
        configure = [bool]$Configure
        verify = -not [bool]$SkipVerify
        log_dir = $LogDir
        steps = $steps
    } | ConvertTo-Json -Depth 6
    exit 0
}

try {
    if ($CleanBuildTree) {
        Clear-AidaBuildTree
    }
    foreach ($step in $steps) {
        Invoke-CmdStep $step
    }
    $message = "Completed in $($Stopwatch.Elapsed). Logs: $LogDir"
    Write-Summary "success" $message 0
    Send-AidaBuildNotification "success" $message
    exit 0
} catch {
    $message = $_.Exception.Message
    Write-Summary "failed" $message 1
    Send-AidaBuildNotification "failed" $message
    Write-Error $message
    exit 1
}
