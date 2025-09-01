
### **Logon-TYPE**

- **DC1/DC2** domain controllers . only admins can do 
- **PKI** 
- **WS001** normal workstartions
- **PAW** privileged admin workstation 

[event codes encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4625)

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

---
#### 🖥️ **Windows System Logs**

| Event ID | Emoji | Name                         | Why it Matters                                                                  |
| -------- | ----- | ---------------------------- | ------------------------------------------------------------------------------- |
| **1074** | 📴    | System Shutdown / Restart    | Shows when & why system shut down/restarted — unexpected ones may be malicious. |
| **6005** | 🟢    | Event Log Service Started    | Marks system boot — good start point for timeline analysis.                     |
| **6006** | 🔴    | Event Log Service Stopped    | Often during shutdown — unexpected stops may hide activity.                     |
| **6013** | ⏳     | Windows Uptime               | Shows daily uptime — short uptime could mean unwanted reboot.                   |
| **7040** | 🔄    | Service Startup Type Changed | Service changed from auto/manual — may indicate tampering.                      |

#### 🔐 **Windows Security Logs**

| Event ID        | Emoji  | Name                            | Why it Matters                                                                  |
| --------------- | ------ | ------------------------------- | ------------------------------------------------------------------------------- |
| **1102**        | 🧹     | Audit Log Cleared               | Often used to hide tracks after intrusion.                                      |
| **1116**        | 🦠     | AV Malware Detection            | Defender spotted malware — monitor for spikes.                                  |
| **1118**        | 🛠️    | AV Remediation Started          | Defender started removing/quarantining malware.                                 |
| **1119**        | ✅      | AV Remediation Succeeded        | Malware cleanup was successful.                                                 |
| **1120**        | ❌      | AV Remediation Failed           | Malware removal failed — urgent action needed.                                  |
| **4624**        | 🔑     | Successful Logon                | Track normal vs. unusual logon patterns.                                        |
| **4625**        | 🚫     | Failed Logon                    | Multiple failures may mean brute-force attack.                                  |
| **4648**        | 👤➡️💻 | Logon with Explicit Credentials | May indicate lateral movement attempts.                                         |
| **4656**        | 📂     | Handle to Object Requested      | Watch for sensitive resource access attempts.                                   |
| **4688**        | ⚙️     | Process Creation                | Logs every new process — critical for detecting malicious tools/scripts usage.  |
| **4672**        | 👑     | Special Privileges Logon        | Admin-level access given — monitor for abuse.                                   |
| **4698**        | ⏰      | Scheduled Task Created          | Attackers use for persistence — suspicious if unexpected.                       |
| **4700 / 4701** | 🔄⏰    | Task Enabled / Disabled         | Changing scheduled tasks could hide malicious jobs.                             |
| **4702**        | ✏️⏰    | Scheduled Task Updated          | Updates to tasks could mean altered malicious jobs.                             |
| **4719**        | 📝     | Audit Policy Changed            | Could be disabling logging to hide actions.                                     |
| **4738**        | 👤✏️   | User Account Changed            | Unexpected changes may mean account takeover.                                   |
| **4771**        | 🛡️    | Kerberos Pre-auth Failed        | Possible brute-force attempt on Kerberos.                                       |
| **4776**        | 🗝️    | Credential Validation Attempt   | Multiple failures may mean credential stuffing.                                 |
| **4907**        | 📝     | Audit Policy Change (Object)    | Shows modifications to object-level auditing, often a sign of evasion attempts. |
| **5001**        | ⚙️🦠   | AV Real-Time Protection Changed | Could indicate disabling security features.                                     |
| **5140**        | 📂🌐   | Network Share Accessed          | Watch for sensitive file access over network.                                   |
| **5142**        | ➕🌐    | Network Share Created           | Could be for data theft or malware spread.                                      |
| **5145**        | 🔍🌐   | Network Share Access Check      | Mapping network shares — possible recon step.                                   |
| **5157**        | 🚫🌐   | Connection Blocked (WFP)        | WFP blocked suspicious network traffic.                                         |
| **7045**        | 🛠️📦  | Service Installed               | Unknown services might be malware.                                              |

---

#### 🖥 **Sysmon Event ID Cheat Sheet**


| **Event ID** | **Name**                     | **Explanation**                                                                                           | **When to Hunt / Example**                                                                                        |
| ------------ | ---------------------------- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| **1** 🛠️    | Process Creation             | Logs every new process created on the system, including parent/child relationships, command line, hashes. | Hunt for suspicious tools (`mimikatz.exe`), LOLBins (`powershell.exe -enc`), malware execution from temp folders. |
| **2** 🗑️    | File Creation Time Changed   | Logs changes to file creation timestamps (timestomping).                                                  | Check for attackers modifying timestamps to evade detection (`cmd.exe /c copy /b file` tricks).                   |
| **3** 🌐     | Network Connection           | Logs outbound TCP/UDP connections from a process, including IPs, ports, domains.                          | Hunt for C2 traffic from unusual processes (`notepad.exe` making HTTP requests).                                  |
| **4** 📦     | Sysmon Service State Changed | Logs when the Sysmon service is installed, stopped, or updated.                                           | Hunt for attempts to disable monitoring before an attack.                                                         |
| **5** 📄     | Process Terminated           | Logs when a process ends.                                                                                 | Rarely used for detection alone; useful in correlation (e.g., short-lived suspicious processes).                  |
| **6** 🔄     | Driver Loaded                | Logs kernel-mode driver loading.                                                                          | Check for unsigned or suspicious drivers (rootkits).                                                              |
| **7** 🧩     | Image Loaded (DLL)           | Logs DLLs loaded into a process.                                                                          | Hunt for malicious DLL injection or LOLBin DLLs (`rundll32.exe`).                                                 |
| **8** 🔐     | CreateRemoteThread           | Logs threads created in another process (code injection).                                                 | Check for process injection techniques (`powershell.exe` injecting into `explorer.exe`).                          |
| **9** 🧠     | RawAccessRead                | Logs processes reading raw disk sectors (bypassing filesystem).                                           | Hunt for disk forensic evasion or credential dumping tools.                                                       |
| **10** 🖇️   | ProcessAccess                | Logs processes accessing memory of another process.                                                       | Check for credential dumping (`lsass.exe` access).                                                                |
| **11** 📥    | File Create                  | Logs newly created files.                                                                                 | Hunt for dropped malware payloads in suspicious directories (`C:\Users\Public\`).                                 |
| **12** 📂    | Registry Object Created      | Logs registry keys created.                                                                               | Look for persistence keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).                                 |
| **13** 📝    | Registry Value Set           | Logs registry values changed.                                                                             | Hunt for changes to `Run` keys or disabling security tools.                                                       |
| **14** 🗑️   | Registry Value Deleted       | Logs deleted registry values.                                                                             | Hunt for removal of forensic evidence.                                                                            |
| **15** 🔍    | FileStream Created           | Logs creation of alternate data streams (ADS).                                                            | Check for hidden malicious code stored in ADS.                                                                    |
| **16** ⚙️    | Sysmon Config Change         | Logs changes to Sysmon configuration.                                                                     | Detect attempts to weaken logging.                                                                                |
| **17** 🔄    | Named Pipe Created           | Logs new named pipes (IPC).                                                                               | Hunt for named pipes used by malware for interprocess comms.                                                      |
| **18** 🔌    | Named Pipe Connected         | Logs connections to named pipes.                                                                          | Check for malware C2 over named pipes.                                                                            |
| **19** 📦    | WMI Event Filter             | Logs creation of WMI event filters.                                                                       | Hunt for WMI persistence (`SELECT * FROM __InstanceModificationEvent`).                                           |
| **20** 🛠️   | WMI Event Consumer           | Logs creation of WMI consumers.                                                                           | Check for malicious WMI payloads.                                                                                 |
| **21** 🔗    | WMI Event Binding            | Logs binding between WMI filter and consumer.                                                             | Hunt for full WMI persistence chains.                                                                             |
| **22** 🌍    | DNS Query                    | Logs DNS requests from a process.                                                                         | Hunt for suspicious domains (`xyz123abc.com`) queried by system processes.                                        |
| **23** 📡    | File Delete (Archived)       | Logs file deletions (archived in Sysmon config).                                                          | Hunt for removal of dropped malware.                                                                              |
| **24** 🛡️   | Clipboard Change             | Logs changes to clipboard content.                                                                        | Rare; could indicate data theft via clipboard monitoring.                                                         |
| **25** 💉    | Process Tampering            | Logs process hollowing, image replacement, or other tampering.                                            | Hunt for malware injecting into legitimate processes.                                                             |
| **26** 🔒    | File Delete (Logged)         | Logs file deletions (without archive).                                                                    | Hunt for attackers cleaning up tools after use.                                                                   |

💡 **Memory Trick:**  
- **1–7** 🖥 = Process & Image stuff.
- **8–10** 🛡 = Security & low-level access.
- **11–14** 📂 = File & Registry changes.
- **19–22** 🌐 = WMI & network queries.
---

https://www.virustotal.com/gui/home/search

