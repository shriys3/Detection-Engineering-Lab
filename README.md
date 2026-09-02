## Detection Engineering Lab: Sysmon + Splunk + Atomic Red Team
A home lab simulating real MITRE ATT&CK techniques with Atomic Red Team, capturing telemetry with Sysmon, and building Splunk detection queries mapped to specific attacker behaviors.

### Objective
This project focuses on the detection aspect of security, using SIEM queries and tools paralleling SOC analyst work. Each query was validated against a triggered live, safe attack simulation.

### Architecture
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

#### 1. Encoded PowerShell Command Execution — T1059.001 

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










