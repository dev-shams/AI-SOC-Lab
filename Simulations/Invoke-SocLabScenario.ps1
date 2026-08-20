[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "EncodedPowerShell",
        "DiscoveryBurst",
        "ScheduledTask",
        "RunKey",
        "Certutil",
        "TemporaryAdmin",
        "All"
    )]
    [string]$Scenario
)

$ErrorActionPreference = "Stop"
$LabRoot = "C:\SOC-Lab\Simulation"
New-Item -Path $LabRoot -ItemType Directory -Force | Out-Null

function Invoke-EncodedPowerShell {
    Write-Host "[EncodedPowerShell] Generating harmless encoded PowerShell telemetry"
    $command = "Write-Output 'SOC-LAB-ENCODED-001'; whoami; hostname"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    powershell.exe -NoProfile -EncodedCommand $encoded
}

function Invoke-DiscoveryBurst {
    Write-Host "[DiscoveryBurst] Running local system and account discovery"
    Write-Output "SOC-LAB-DISCOVERY-001"
    whoami.exe /all | Out-Null
    hostname.exe | Out-Null
    ipconfig.exe /all | Out-Null
    net.exe user | Out-Null
    net.exe localgroup Administrators | Out-Null
    tasklist.exe | Out-Null
}

function Invoke-ScheduledTask {
    $taskName = "SOC-Lab-Benign-Task"
    Write-Host "[ScheduledTask] Creating and removing $taskName"
    try {
        $action = New-ScheduledTaskAction -Execute "cmd.exe" `
            -Argument "/c echo SOC-LAB-TASK-001"
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1)
        Register-ScheduledTask -TaskName $taskName -Action $action `
            -Trigger $trigger -Description "AI SOC lab benign simulation" -Force | Out-Null
        Get-ScheduledTask -TaskName $taskName | Out-Null
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
}

function Invoke-RunKey {
    $runPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $valueName = "SocLabBenignRun"
    Write-Host "[RunKey] Creating and immediately removing a benign Run value"
    try {
        New-Item -Path $runPath -Force | Out-Null
        New-ItemProperty -Path $runPath -Name $valueName -PropertyType String `
            -Value "cmd.exe /c echo SOC-LAB-RUNKEY-001" -Force | Out-Null
        Get-ItemProperty -Path $runPath -Name $valueName | Out-Null
    }
    finally {
        Remove-ItemProperty -Path $runPath -Name $valueName -ErrorAction SilentlyContinue
    }
}

function Invoke-Certutil {
    $source = Join-Path $LabRoot "benign.txt"
    $encoded = Join-Path $LabRoot "benign.txt.b64"
    Write-Host "[Certutil] Encoding a harmless local marker file"
    try {
        Set-Content -Path $source -Value "SOC-LAB-CERTUTIL-001" -Encoding Ascii
        certutil.exe -encode $source $encoded | Out-Null
    }
    finally {
        Remove-Item -Path $source, $encoded -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-TemporaryAdmin {
    $name = "soc_lab_temp_admin"
    Write-Host "[TemporaryAdmin] Creating, elevating, and removing $name"
    $password = ConvertTo-SecureString ([Guid]::NewGuid().ToString()) -AsPlainText -Force
    try {
        if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
            New-LocalUser -Name $name -Password $password `
                -Description "AI SOC lab temporary admin simulation" | Out-Null
        }
        Add-LocalGroupMember -Group "Administrators" -Member $name
        Write-Output "SOC-LAB-TEMP-ADMIN-001"
    }
    finally {
        Remove-LocalGroupMember -Group "Administrators" -Member $name -ErrorAction SilentlyContinue
        Remove-LocalUser -Name $name -ErrorAction SilentlyContinue
    }
}

$scenarios = if ($Scenario -eq "All") {
    @(
        "EncodedPowerShell",
        "DiscoveryBurst",
        "ScheduledTask",
        "RunKey",
        "Certutil",
        "TemporaryAdmin"
    )
}
else {
    @($Scenario)
}

foreach ($item in $scenarios) {
    switch ($item) {
        "EncodedPowerShell" { Invoke-EncodedPowerShell }
        "DiscoveryBurst" { Invoke-DiscoveryBurst }
        "ScheduledTask" { Invoke-ScheduledTask }
        "RunKey" { Invoke-RunKey }
        "Certutil" { Invoke-Certutil }
        "TemporaryAdmin" { Invoke-TemporaryAdmin }
    }
}

Write-Host "Completed: $($scenarios -join ', ')"
