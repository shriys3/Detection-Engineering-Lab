## Detection Engineering Lab: Sysmon + Splunk + Atomic Red Team
A home lab simulating real MITRE ATT&CK techniques with Atomic Red Team, capturing telemetry with Sysmon, and building Splunk detection queries mapped to specific attacker behaviors.

### Objective
This project focuses on the detection aspect of security, using SIEM queries and tools paralleling SOC analyst work. Each query was validated against a triggered live, safe attack simulation.

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

insert image here 

**What it caught:** A `powershell.exe` process launched with `-e <base64>`, spawned from `cmd.exe`. This process pattern of a PowerShell launched by cmd rather than directly by a user is an indicator worth flagging.

insert images here 




### 2. Scheduled Task Creation — [T1053.005](https://attack.mitre.org/techniques/T1053/005/)
**Tactic:** Persistence
 
Attackers use the Windows Task Scheduler to establish persistence. This ensures their access to a system survives a reboot or re-executes later without further interaction. `schtasks.exe` is a legitimate system binary, meaning it is the actual Windows program that creates scheduled tasks. As detection cannot only flag this value, it must combine that with the `/Create` action and its invocation via `cmd.exe` rather than the Task Scheduler GUI. Being launched from the command line, especially chained inside another command, is a pattern much more associated with scripts and automation that attackers are more likely to deploy. 
 
**Simulated with:** `Invoke-AtomicTest T1053.005 -TestNumbers 2`
 
**Detection query:**
```spl
index=* sourcetype=*sysmon* EventCode=1 Image=*schtasks.exe* CommandLine="*Create*"
```
 
**Attack simulation:**
 
insert image here 

 
**What it caught:** `schtasks.exe /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10` a scheduled task set to relaunch `cmd.exe` at a specified time, spawned from `cmd.exe` itself.
 
 
insert images





### 3. System Information Discovery — [T1082](https://attack.mitre.org/techniques/T1082/)
**Tactic:** Discovery
 
Most intrusions begin with an attacker conducting reconnaissance, orienting themselves on the compromised host by checking OS version, patch level, hardware, network configuration. `systeminfo.exe` is Windows' built-in tool that surfaces this information, making it a common thing analysts watch for to signal reconnaissance. 
 
**Simulated with:** `Invoke-AtomicTest T1082 -TestNumbers 1`
 
**Detection query:**
```spl
index=* sourcetype=*sysmon* EventCode=1 Image=*systeminfo.exe*
```
 
**Attack simulation:**
 
insert image
 
**What it caught:** `systeminfo.exe` was launched from the command interface `cmd.exe`, alongside a chained `reg query` command against a path leading to the Windows registry hardware database. Both gather two differnt categories of information (host info + hardware enumeration) in a single command chain, signaling a possible attacker recon action.
 
images insert here 


## MITRE ATT&CK Coverage
 
| Tactic | Technique | ID |
|---|---|---|
| Execution | PowerShell | T1059.001 |
| Persistence | Scheduled Task/Job | T1053.005 |
| Discovery | System Information Discovery | T1082 |
 

## Generated Splunk Reports/Alerts 

insert 


## Other Notes
 
- Sysmon config: [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- All detections were validated live by triggering the corresponding Atomic Red Team test and confirming the query returned the resulting event
- Running on Splunk's Free license, which doesn't support scheduled/alerting searches — so detections were saved as Reports and re-run manually. In a production Splunk Enterprise or Cloud deployment, these would be deployed as scheduled alerts with notification actions.
  
## Outcomes
- Building a working telemetry pipeline from raw endpoint activity to searchable SIEM data
- Translating MITRE ATT&CK techniques into a concrete, testable detection query
- Understanding why a detection works and its context to pattern match based on multiple indicators
- Validating detections against live, controlled attack simulation








