## Detection Engineering Lab: Sysmon + Splunk + Atomic Red Team
A home lab simulating real MITRE ATT&CK techniques with Atomic Red Team, capturing telemetry with Sysmon, and building Splunk detection queries mapped to specific attacker behaviors.

### Objective
This project focuses on the detection aspect of security, using SIEM queries and tools paralleling components of a SOC detection workflow. Each query was validated against a triggered live, safe attack simulation.

### Architecture
```
┌─────────────────────────┐         ┌──────────────────────────┐
│   Windows 11 ARM64 VM   │         │   macOS (Apple Silicon)   │
│   (UTM, Attacker/Victim) │         │                            │
│                          │         │                            │
│  Sysmon (SwiftOnSecurity │  9997   │   Splunk Enterprise        │
│  config) ─── captures ─▶│ ──────▶ │   (Free license)           │
│                          │  (UTM   │                            │
│  Splunk Universal        │  shared │   Search, detection rules, │
│  Forwarder ─── ships ───▶│  network)│  saved reports            │
│                          │         │                            │
│  Atomic Red Team ────────┤         │                            │
│  (simulates ATT&CK       │         │                            │
│   techniques)            │         │                            │
└─────────────────────────┘         └──────────────────────────┘
```
**Setup Justification**: Host machine runs on Apple Silicon, which is where the Splunk SIEM was deployed directly (via Rosetta 2). In a UTM-hosted VM running Windows 11 (victim), logs were forwarded over UTM's shared virtual network. Sysmon itself required the ARM64-specific binary (Sysmon64a.exe) since kernel-mode drivers can't be emulated across architectures. However, user-mode tools like the Splunk forwarder run effectively under x64 emulation.

### Tools Used

| Tool | Purpose |
|---|---|
| [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) (SwiftOnSecurity config) | High-fidelity Windows telemetry (process creation, network, registry) |
| [Splunk Enterprise](https://www.splunk.com/) (Free license) | SIEM — ingestion, search, detection queries |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Safe, controlled MITRE ATT&CK technique simulation |
| UTM Virtualization | Hypervisor supporting MacOS. (Windows 11 ARM64 victim host) |
 

### Detections Built
Three detections spanning three distinct MITRE ATT&CK tactics — chosen to demonstrate tactic diversity.

### 1. Encoded PowerShell Command Execution — [T1059.001](https://attack.mitre.org/techniques/T1059/001/)

**Tactic:** Execution 

Attackers frequently pass malicious PowerShell commands as Base64-encoded strings via the -EncodedCommand flag (abbreviations include -e, -en, -enc) to evade human review and simple text-based detection. This detection flags any PowerShell process launched with an encoded command flag.

**Simulated with:** `Invoke-AtomicTest T1059.001 -TestNumbers 17`


**Detection query:**
```spl
index=* sourcetype=*sysmon* EventCode=1 Image=*powershell.exe*
CommandLine="* -e *" OR CommandLine="* -en *" OR CommandLine="* -enc *" OR CommandLine="* -EncodedCommand *"
```

**Attack simulation:**

<img width="1418" height="562" alt="powershell execution" src="https://github.com/user-attachments/assets/4bd17cb8-a193-4b18-8736-8831a5c72d70" />



**What it caught:** A `powershell.exe` process launched with `-e <base64>`, spawned from `cmd.exe`. This process pattern of a PowerShell launched by cmd with an encoded command, rather than directly by a user, can be an indicator worth flagging.

**Detection considerations:** Encoded PowerShell commands aren't inherently malicious and may be used legitimately by administrative scripts. However, encoded execution can warrant investigation when combined with suspicious parent processes or other unusual activity. A more refined tuning could more comprehensively incorporate parent process, context, and analysis of the decoded command to reduce false positives.

**Search results:**
<img width="1726" height="754" alt="Encoded Powershell" src="https://github.com/user-attachments/assets/dcd87e31-8474-46de-b364-ef061d626627" />

<img width="1362" height="847" alt="Encoded Powershell result" src="https://github.com/user-attachments/assets/73188a76-760e-4f54-9402-d7e876eea8f1" />


### 2. Scheduled Task Creation — [T1053.005](https://attack.mitre.org/techniques/T1053/005/)
**Tactic:** Persistence
 
Attackers use the Windows Task Scheduler to establish persistence. This ensures their access to a system survives a reboot or re-executes later without further interaction. `schtasks.exe` is a legitimate system binary, meaning it is the actual Windows program that creates scheduled tasks. As detection cannot only flag this value, it must combine that with the `/Create` action and its invocation via `cmd.exe` rather than the Task Scheduler GUI. Being launched from the command line, especially chained inside another command, is a pattern much more associated with scripts and automation.
 
**Simulated with:** `Invoke-AtomicTest T1053.005 -TestNumbers 2`
 
**Detection query:**
```spl
index=* sourcetype=*sysmon* EventCode=1 Image=*schtasks.exe* CommandLine="*Create*" ParentImage=*cmd.exe*
```
 
**Attack simulation:**
 
<img width="972" height="592" alt="scheduled task execution" src="https://github.com/user-attachments/assets/9e49627b-1256-4c32-a18b-d1efa414c0ff" />
 
**What it caught:** `schtasks.exe /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10` a scheduled task set to relaunch `cmd.exe` at a specified time, spawned from `cmd.exe` itself.

**Detection considerations:** Scheduled tasks are often created for legitimate administrative and software operations, so schtasks.exe /Create alone does not indicate malicious activity. Requiring a cmd.exe parent narrows this detection to command-line task creation, but legitimate scripts may still trigger it. Additional refinement could consider the task name, execution path and context, and the program specified by /TR.

 **Search results:**
 <img width="1728" height="770" alt="Scheduled Task Creation" src="https://github.com/user-attachments/assets/392e89f5-5b26-4d7a-bdec-f7116763f306" />

 
<img width="1362" height="858" alt="Scheduled Task Creation result" src="https://github.com/user-attachments/assets/f8880f50-f865-4222-aa23-07a7306064df" />



### 3. System Information Discovery — [T1082](https://attack.mitre.org/techniques/T1082/)
**Tactic:** Discovery
 
Most intrusions begin with an attacker conducting reconnaissance, orienting themselves on the compromised host by checking OS version, patch level, hardware, network configuration. `systeminfo.exe` is Windows' built-in tool that surfaces this information, making it a common thing analysts watch for to signal reconnaissance. 
 
**Simulated with:** `Invoke-AtomicTest T1082 -TestNumbers 1`
 
**Detection query:**
```spl
index=* sourcetype=*sysmon* EventCode=1 Image=*systeminfo.exe*
```
 
**Attack simulation:**
 

<img width="1260" height="896" alt="discovery execution" src="https://github.com/user-attachments/assets/6482a23b-ac0f-4a69-a5ce-5d61b74a866d" />


 
**What it caught:** `systeminfo.exe` was launched from the command interface `cmd.exe`, alongside a chained `reg query` command against a path leading to the Windows registry hardware database. Both gather two differnt categories of information (host info + hardware enumeration) in a single command chain, consistent with possible attacker recon behavior.

**Detection considerations:** systeminfo.exe is a legitimate Windows utility, so its execution alone is a low-confidence indicator and may generate false positives from normal activity. It becomes more meaningful when correlated with other discovery commands, unusual parent processes, or suspicious activity happening in a similar timeframe. In this project, systeminfo.exe was executed alongside a registry query used to enumerate hardware information, which provides additional context consistent with system reconnaissance.

 **Search results:**
<img width="1727" height="727" alt="discovery" src="https://github.com/user-attachments/assets/d037e7c1-9f0d-4e24-a023-23d09a9d616f" />

<img width="1359" height="857" alt="discovery result" src="https://github.com/user-attachments/assets/d44a20e4-de37-40d4-b7a9-a3a8b3ca19f2" />


## MITRE ATT&CK Coverage
 
| Tactic | Technique | ID |
|---|---|---|
| Execution | PowerShell | T1059.001 |
| Persistence | Scheduled Task/Job | T1053.005 |
| Discovery | System Information Discovery | T1082 |
 

## Generated Splunk Reports

<img width="1470" height="548" alt="reports" src="https://github.com/user-attachments/assets/9e4f45cd-1055-483e-aa68-fa7876027f65" />

## Other Notes
 
- Sysmon config: [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- All detections were validated live by triggering the corresponding Atomic Red Team test and confirming the query returned the resulting event
- Running on Splunk's Free license, which doesn't support scheduled/alerting searches — so detections were saved as Reports and re-run manually. In a production Splunk Enterprise or Cloud deployment, these would be deployed as scheduled alerts with notification actions.
  
## Outcomes
- Building a working telemetry pipeline from raw endpoint activity to searchable SIEM data
- Translating MITRE ATT&CK techniques into a concrete, testable detection query
- Understanding why a detection works and its context to pattern match based on multiple indicators
- Validating detections against live, controlled attack simulation







