![windows event logo](../attachments/Pasted%20image%2020250809101351.png)

- Windows Event Logs are like **a diary your computer keeps**, recording almost everything that happens — from program errors to someone logging in.

**Main log categories:**
- **Application** → What apps have been up to (errors, crashes, start/stop events).
- **System** → Hardware, drivers, and Windows internals.
- **Security** → Logons, logoffs, privilege changes, file access attempts.
- **Setup** → Installation/configuration changes.
- **Forwarded Events** → Logs from other computers (centralized monitoring).

we can use **Event Viewer** or we can use **API** and **saved log files(.evtx)** into event viewer 

#### Anatomy of an event log

| Field             | What it Means                                                  |
| ----------------- | -------------------------------------------------------------- |
| **Log Name**      | Which diary section this is from.                              |
| **Source**        | Who wrote it (software/app/service).                           |
| **Event ID**      | Unique code for the type of event.                             |
| **Task Category** | Short label for the type of task.                              |
| **Level**         | Severity (Info, Warning, Error, Critical, Verbose).            |
| **Keywords**      | Tags to group events (e.g., "Audit Success", "Audit Failure"). |
| **User**          | Account that triggered the event.                              |
| **OpCode**        | The specific operation.                                        |
| **Logged**        | Date/time.                                                     |
| **Computer**      | Name of the machine.                                           |
| **XML Data**      | Raw detailed data.                                             |

#### 🖥️ **Windows System Logs**

|Event ID|Emoji|Name|Why it Matters|
|---|---|---|---|
|**1074**|📴|System Shutdown / Restart|Shows when & why system shut down/restarted — unexpected ones may be malicious.|
|**6005**|🟢|Event Log Service Started|Marks system boot — good start point for timeline analysis.|
|**6006**|🔴|Event Log Service Stopped|Often during shutdown — unexpected stops may hide activity.|
|**6013**|⏳|Windows Uptime|Shows daily uptime — short uptime could mean unwanted reboot.|
|**7040**|🔄|Service Startup Type Changed|Service changed from auto/manual — may indicate tampering.|

#### 🔐 **Windows Security Logs**

|Event ID|Emoji|Name|Why it Matters|
|---|---|---|---|
|**1102**|🧹|Audit Log Cleared|Often used to hide tracks after intrusion.|
|**1116**|🦠|AV Malware Detection|Defender spotted malware — monitor for spikes.|
|**1118**|🛠️|AV Remediation Started|Defender started removing/quarantining malware.|
|**1119**|✅|AV Remediation Succeeded|Malware cleanup was successful.|
|**1120**|❌|AV Remediation Failed|Malware removal failed — urgent action needed.|
|**4624**|🔑|Successful Logon|Track normal vs. unusual logon patterns.|
|**4625**|🚫|Failed Logon|Multiple failures may mean brute-force attack.|
|**4648**|👤➡️💻|Logon with Explicit Credentials|May indicate lateral movement attempts.|
|**4656**|📂|Handle to Object Requested|Watch for sensitive resource access attempts.|
|**4672**|👑|Special Privileges Logon|Admin-level access given — monitor for abuse.|
|**4698**|⏰|Scheduled Task Created|Attackers use for persistence — suspicious if unexpected.|
|**4700 / 4701**|🔄⏰|Task Enabled / Disabled|Changing scheduled tasks could hide malicious jobs.|
|**4702**|✏️⏰|Scheduled Task Updated|Updates to tasks could mean altered malicious jobs.|
|**4719**|📝|Audit Policy Changed|Could be disabling logging to hide actions.|
|**4738**|👤✏️|User Account Changed|Unexpected changes may mean account takeover.|
|**4771**|🛡️|Kerberos Pre-auth Failed|Possible brute-force attempt on Kerberos.|
|**4776**|🗝️|Credential Validation Attempt|Multiple failures may mean credential stuffing.|
|**5001**|⚙️🦠|AV Real-Time Protection Changed|Could indicate disabling security features.|
|**5140**|📂🌐|Network Share Accessed|Watch for sensitive file access over network.|
|**5142**|➕🌐|Network Share Created|Could be for data theft or malware spread.|
|**5145**|🔍🌐|Network Share Access Check|Mapping network shares — possible recon step.|
|**5157**|🚫🌐|Connection Blocked (WFP)|WFP blocked suspicious network traffic.|
|**7045**|🛠️📦|Service Installed|Unknown services might be malware.|

```shell-session
xfreerdp /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /v:[Target IP] /dynamic-resolution
```


#### question

1. Analyze the event with ID 4624, that took place on 8/3/2022 at 10:23:25. Conduct a similar investigation as outlined in this section and provide the name of the executable responsible for the modification of the auditing settings as your answer. Answer format: T_W_____.exe
`  `


![some image ](../attachments/Pasted%20image%2020250809105520.png)


