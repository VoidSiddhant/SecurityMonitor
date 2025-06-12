# Security Monitor Script - Protects against remote access and malicious processes
# Created for dangerous network environment protection

Param(
    [switch]$Continuous,
    [int]$IntervalSeconds = 30,
    [switch]$Verbose,
    [switch]$LogToFile,
    [string]$LogPath = "SecurityMonitor.log"
)

# Define suspicious processes to monitor
$SuspiciousProcesses = @(
    "TeamViewer", "teamviewer", "tv_w32", "tv_x64",
    "AnyDesk", "anydesk",
    "remoting_host", "Chrome Remote Desktop",
    "VNC", "vnc", "vncserver", "vncviewer",
    "LogMeIn", "logmein", "LMIGuardianSvc",
    "Splashtop", "splashtop",
    "GoToAssist", "gotoassist",
    "Ammyy", "ammyy",
    "UltraVNC", "ultravnc",
    "RealVNC", "realvnc",
    "TightVNC", "tightvnc",
    "RemotePC", "remotepc",
    "mstsc", "rdpclip", "tstheme",
    "psexec", "psexesvc",
    "winrm", "wsmprovhost",
    "nmap", "masscan", "zmap",
    "netcat", "nc", "ncat",
    "wireshark", "tshark",
    "rat", "backdoor", "trojan",
    "njrat", "darkcomet", "blackshades",
    "putty", "plink", "pscp",
    "ssh", "scp", "sftp",
    "telnet", "ftp"
)

# Suspicious ports to monitor
$SuspiciousPorts = @(3389, 5900, 5938, 7070, 22, 23, 80, 443, 4444, 1337, 31337, 8080, 9999)

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if ($Verbose -or $Level -eq "WARNING" -or $Level -eq "CRITICAL") {
        $color = "Green"
        if ($Level -eq "WARNING") { $color = "Yellow" }
        if ($Level -eq "CRITICAL") { $color = "Red" }
        Write-Host $logMessage -ForegroundColor $color
    }
    
    if ($LogToFile) {
        Add-Content -Path $LogPath -Value $logMessage
    }
}

function Get-SuspiciousProcesses {
    Write-Log "Scanning for suspicious processes..."
    $suspiciousFound = @()
    $allProcesses = Get-Process
    
    foreach ($process in $allProcesses) {
        foreach ($suspiciousName in $SuspiciousProcesses) {
            if ($process.ProcessName -like "*$suspiciousName*" -or $process.ProcessName -eq $suspiciousName) {
                $processPath = "Access Denied"
                $processCompany = "Unknown"
                try { $processPath = $process.Path } catch { }
                try { $processCompany = $process.Company } catch { }
                
                $processInfo = New-Object PSObject -Property @{
                    ProcessName = $process.ProcessName
                    PID = $process.Id
                    Path = $processPath
                    Company = $processCompany
                }
                
                $suspiciousFound += $processInfo
                Write-Log "SUSPICIOUS PROCESS: $($process.ProcessName) (PID: $($process.Id))" "WARNING"
            }
        }
    }
    return $suspiciousFound
}

function Get-SuspiciousNetworkConnections {
    Write-Log "Scanning for suspicious network connections..."
    $suspiciousConnections = @()
    
    try {
        $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
        foreach ($conn in $connections) {
            if ($conn.RemotePort -in $SuspiciousPorts -or $conn.LocalPort -in $SuspiciousPorts) {
                $processName = "Unknown"
                try {
                    $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                    if ($process) { $processName = $process.ProcessName }
                } catch { }
                
                $connectionInfo = New-Object PSObject -Property @{
                    LocalAddress = $conn.LocalAddress
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    ProcessName = $processName
                    PID = $conn.OwningProcess
                }
                
                $suspiciousConnections += $connectionInfo
                Write-Log "SUSPICIOUS CONNECTION: $($conn.RemoteAddress):$($conn.RemotePort) (Process: $processName)" "WARNING"
            }
        }
    } catch {
        Write-Log "Error scanning network connections: $($_.Exception.Message)" "WARNING"
    }
    return $suspiciousConnections
}

function Get-ScreenShareSessions {
    Write-Log "Checking for active screen share sessions..."
    $screenShareSessions = @()
    
    # Check for RDP clipboard process
    $clipboardProcess = Get-Process -Name "rdpclip" -ErrorAction SilentlyContinue
    if ($clipboardProcess) {
        $screenShareSessions += "RDP Clipboard Process Active"
        Write-Log "RDP CLIPBOARD DETECTED - Possible remote session" "CRITICAL"
    }
    
    # Check for active RDP sessions
    try {
        $output = quser 2>$null
        if ($output) {
            foreach ($line in $output) {
                if ($line -match "rdp" -or $line -match "console") {
                    $screenShareSessions += "User Session: $line"
                    Write-Log "ACTIVE SESSION: $line" "WARNING"
                }
            }
        }
    } catch {
        Write-Log "Could not check user sessions" "WARNING"
    }
    
    return $screenShareSessions
}

function Start-SecurityScan {
    Write-Log "=== SECURITY SCAN STARTED ===" "INFO"
    
    # Get system info
    $computerName = $env:COMPUTERNAME
    $username = $env:USERNAME
    Write-Log "System: $computerName | User: $username"
    
    # Perform scans
    $suspiciousProcesses = Get-SuspiciousProcesses
    $screenShareSessions = Get-ScreenShareSessions
    $suspiciousConnections = Get-SuspiciousNetworkConnections
    
    $totalThreats = $suspiciousProcesses.Count + $screenShareSessions.Count + $suspiciousConnections.Count
    
    # Display summary
    Write-Host "`n=== SECURITY SCAN SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Scan Time: $(Get-Date)" -ForegroundColor Gray
    Write-Host "Suspicious Processes Found: $($suspiciousProcesses.Count)" -ForegroundColor $(if($suspiciousProcesses.Count -gt 0) {"Red"} else {"Green"})
    Write-Host "Screen Share Sessions: $($screenShareSessions.Count)" -ForegroundColor $(if($screenShareSessions.Count -gt 0) {"Red"} else {"Green"})
    Write-Host "Suspicious Network Connections: $($suspiciousConnections.Count)" -ForegroundColor $(if($suspiciousConnections.Count -gt 0) {"Red"} else {"Green"})
    Write-Host "Total Potential Threats: $totalThreats" -ForegroundColor $(if($totalThreats -gt 0) {"Red"} else {"Green"})
    
    if ($totalThreats -eq 0) {
        Write-Host "`nNo obvious threats detected!" -ForegroundColor Green
    } else {
        Write-Host "`nPOTENTIAL SECURITY THREATS DETECTED!" -ForegroundColor Red
        Write-Host "Review the detailed log above for specific findings." -ForegroundColor Yellow
    }
    
    Write-Log "=== SECURITY SCAN COMPLETED ===" "INFO"
    
    # Return results object
    return New-Object PSObject -Property @{
        SuspiciousProcesses = $suspiciousProcesses
        ScreenShareSessions = $screenShareSessions
        SuspiciousConnections = $suspiciousConnections
        TotalThreats = $totalThreats
    }
}

# Main execution
Write-Host "Security Monitor v1.0" -ForegroundColor Cyan
Write-Host "Monitoring for screen sharing and suspicious remote access processes..." -ForegroundColor Gray
Write-Host ""

if ($LogToFile) {
    Write-Log "Logging enabled. Log file: $LogPath"
}

if ($Continuous) {
    Write-Host "Continuous monitoring enabled. Press Ctrl+C to stop." -ForegroundColor Yellow
    Write-Host ""
    
    while ($true) {
        try {
            Start-SecurityScan | Out-Null
            Write-Host "`nNext scan in $IntervalSeconds seconds..." -ForegroundColor Gray
            Start-Sleep -Seconds $IntervalSeconds
            Clear-Host
        } catch {
            Write-Log "Error during continuous monitoring: $($_.Exception.Message)" "WARNING"
            Start-Sleep -Seconds 5
        }
    }
} else {
    # Single scan
    $result = Start-SecurityScan
    
    if ($Verbose) {
        Write-Host "`n=== DETAILED RESULTS ===" -ForegroundColor Cyan
        
        if ($result.SuspiciousProcesses.Count -gt 0) {
            Write-Host "`nSuspicious Processes:" -ForegroundColor Red
            $result.SuspiciousProcesses | Format-Table -AutoSize
        }
        
        if ($result.SuspiciousConnections.Count -gt 0) {
            Write-Host "`nSuspicious Network Connections:" -ForegroundColor Red
            $result.SuspiciousConnections | Format-Table -AutoSize
        }
        
        if ($result.ScreenShareSessions.Count -gt 0) {
            Write-Host "`nScreen Share Sessions:" -ForegroundColor Red
            $result.ScreenShareSessions | ForEach-Object { Write-Host "  - $_" }
        }
    }
}

Write-Host "`nScan completed. Stay vigilant!" -ForegroundColor Green

