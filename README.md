# Security Monitor Usage Guide

This PowerShell script monitors your Windows system for potentially malicious processes, active screen sharing sessions, and suspicious network connections that could indicate unauthorized remote access.

## Quick Start

### Basic Scan (Recommended)
```powershell
.\SecurityMonitor.ps1
```

### Detailed Scan with Verbose Output
```powershell
.\SecurityMonitor.ps1 -Verbose
```

### Continuous Monitoring
```powershell
.\SecurityMonitor.ps1 -Continuous -IntervalSeconds 30
```

### Log to File
```powershell
.\SecurityMonitor.ps1 -LogToFile -LogPath "security_log.txt"
```

## Parameters

- `-Continuous`: Run continuous monitoring (press Ctrl+C to stop)
- `-IntervalSeconds`: Seconds between scans in continuous mode (default: 30)
- `-Verbose`: Show detailed information about all findings
- `-LogToFile`: Enable logging to file
- `-LogPath`: Specify log file path (default: "SecurityMonitor.log")

## What It Detects

### Screen Sharing Applications
- TeamViewer
- AnyDesk
- Chrome Remote Desktop
- VNC variants (UltraVNC, RealVNC, TightVNC)
- LogMeIn
- Splashtop
- And many others...

### Remote Access Tools
- RDP sessions and processes
- PSExec
- WinRM
- SSH/Telnet clients
- PowerShell remoting

### Suspicious Network Connections
Monitors for connections on common backdoor and remote access ports:
- 3389 (RDP)
- 5900 (VNC)
- 5938 (TeamViewer)
- 7070 (AnyDesk)
- 22 (SSH)
- 4444, 1337, 31337, 9999 (Common backdoor ports)

### Potential Malware
- Known RAT (Remote Access Trojan) signatures
- Network scanning tools
- Backdoor processes

## Security Recommendations

### If Threats Are Detected:
1. **Don't panic** - Some detections may be legitimate (e.g., your own TeamViewer installation)
2. **Investigate** - Check if you recognize the processes
3. **Terminate suspicious processes** if you're certain they're malicious
4. **Disconnect from network** if you suspect active compromise
5. **Run antivirus scan**
6. **Change passwords** for critical accounts
7. **Contact IT security** if in a corporate environment

### Prevention Tips:
1. Keep Windows and antivirus updated
2. Use Windows Firewall or third-party firewall
3. Avoid suspicious downloads and email attachments
4. Use strong, unique passwords
5. Enable Windows Defender or use reputable antivirus
6. Regularly monitor system with this script

## Example Output

```
Security Monitor v1.0
Monitoring for screen sharing and suspicious remote access processes...

=== SECURITY SCAN SUMMARY ===
Scan Time: 6/7/2025 2:26:46 AM
Suspicious Processes Found: 1
Screen Share Sessions: 0
Suspicious Network Connections: 2
Total Potential Threats: 3

⚠ POTENTIAL SECURITY THREATS DETECTED!
Review the detailed log above for specific findings.
```

## Limitations

- This tool provides detection, not protection
- Some legitimate software may be flagged as suspicious
- Advanced malware may evade detection
- Requires Administrator privileges for full functionality
- Network connections analysis requires Windows 8/Server 2012 or later

## Running with Administrator Privileges

For best results, run PowerShell as Administrator:
1. Right-click PowerShell
2. Select "Run as Administrator"
3. Navigate to script directory
4. Run the script

## Regular Monitoring

For ongoing protection in a dangerous network environment:

```powershell
# Run every 5 minutes with logging
.\SecurityMonitor.ps1 -Continuous -IntervalSeconds 300 -LogToFile -Verbose
```

## Troubleshooting

### Execution Policy Error
If you get an execution policy error:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
```

### Permission Errors
Some features require Administrator privileges. Run PowerShell as Administrator for full functionality.

### False Positives
If legitimate software is being flagged, you can modify the `$SuspiciousProcesses` array in the script to remove specific entries.

---

**Remember: This tool is for detection and monitoring. It does not provide real-time protection. Use it as part of a comprehensive security strategy.**

