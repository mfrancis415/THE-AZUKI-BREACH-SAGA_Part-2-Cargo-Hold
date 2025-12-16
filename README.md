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


