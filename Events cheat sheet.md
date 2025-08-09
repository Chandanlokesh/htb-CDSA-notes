
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

| Event ID        | Emoji  | Name                            | Why it Matters                                            |
| --------------- | ------ | ------------------------------- | --------------------------------------------------------- |
| **1102**        | 🧹     | Audit Log Cleared               | Often used to hide tracks after intrusion.                |
| **1116**        | 🦠     | AV Malware Detection            | Defender spotted malware — monitor for spikes.            |
| **1118**        | 🛠️    | AV Remediation Started          | Defender started removing/quarantining malware.           |
| **1119**        | ✅      | AV Remediation Succeeded        | Malware cleanup was successful.                           |
| **1120**        | ❌      | AV Remediation Failed           | Malware removal failed — urgent action needed.            |
| **4624**        | 🔑     | Successful Logon                | Track normal vs. unusual logon patterns.                  |
| **4625**        | 🚫     | Failed Logon                    | Multiple failures may mean brute-force attack.            |
| **4648**        | 👤➡️💻 | Logon with Explicit Credentials | May indicate lateral movement attempts.                   |
| **4656**        | 📂     | Handle to Object Requested      | Watch for sensitive resource access attempts.             |
| **4688**        |        |                                 |                                                           |
| **4672**        | 👑     | Special Privileges Logon        | Admin-level access given — monitor for abuse.             |
| **4698**        | ⏰      | Scheduled Task Created          | Attackers use for persistence — suspicious if unexpected. |
| **4700 / 4701** | 🔄⏰    | Task Enabled / Disabled         | Changing scheduled tasks could hide malicious jobs.       |
| **4702**        | ✏️⏰    | Scheduled Task Updated          | Updates to tasks could mean altered malicious jobs.       |
| **4719**        | 📝     | Audit Policy Changed            | Could be disabling logging to hide actions.               |
| **4738**        | 👤✏️   | User Account Changed            | Unexpected changes may mean account takeover.             |
| **4771**        | 🛡️    | Kerberos Pre-auth Failed        | Possible brute-force attempt on Kerberos.                 |
| **4776**        | 🗝️    | Credential Validation Attempt   | Multiple failures may mean credential stuffing.           |
| **4907**        |        |                                 |                                                           |
| **5001**        | ⚙️🦠   | AV Real-Time Protection Changed | Could indicate disabling security features.               |
| **5140**        | 📂🌐   | Network Share Accessed          | Watch for sensitive file access over network.             |
| **5142**        | ➕🌐    | Network Share Created           | Could be for data theft or malware spread.                |
| **5145**        | 🔍🌐   | Network Share Access Check      | Mapping network shares — possible recon step.             |
| **5157**        | 🚫🌐   | Connection Blocked (WFP)        | WFP blocked suspicious network traffic.                   |
| **7045**        | 🛠️📦  | Service Installed               | Unknown services might be malware.                        |

---

#### 🖥 **Sysmon Event ID Cheat Sheet**

##### **Process & Executables**

|Event ID|Description|Emoji Memory Cue|
|---|---|---|
|**1**|**Process Creation** (who/what started)|🚀 _(something launches)_|
|**2**|**File Creation Time Changed**|⏳ _(time altered)_|
|**5**|**Process Terminated**|🛑 _(stop sign)_|
|**6**|**Driver Loaded**|🚚 _(driver delivery)_|
|**7**|**Image Loaded** (DLLs/modules)|🖼 _(picture loading)_|

##### **Network & Connections**

|Event ID|Description|Emoji Memory Cue|
|---|---|---|
|**3**|**Network Connection Detected**|🌐 _(internet globe)_|
|**22**|**DNS Query**|❓🌐 _(ask the internet)_|

#####  **File & Registry Activity**

| Event ID | Description                         | Emoji Memory Cue      |
| -------- | ----------------------------------- | --------------------- |
| **11**   | **File Created**                    | 📄 _(new file)_       |
| **12**   | **Registry Object Created/Deleted** | 🗂 _(folder changes)_ |
| **13**   | **Registry Value Set**              | 📝 _(edit note)_      |
| **14**   | **Registry Object Renamed**         | 🔄 _(rename arrow)_   |


#####  **Security / Access Changes**

| Event ID | Description                               | Emoji Memory Cue       |
| -------- | ----------------------------------------- | ---------------------- |
| **8**    | **Create Remote Thread** (code injection) | 🎯 _(targeted attack)_ |
| **9**    | **Raw Access to Disk**                    | 💽 _(hard disk)_       |
| **10**   | **Process Access** (OpenProcess)          | 🕵️ _(snooping)_       |

#####  **WMI & Other Special Events**

| Event ID | Description                     | Emoji Memory Cue     |
| -------- | ------------------------------- | -------------------- |
| **19**   | **WMI Event Filter Activity**   | 🧪 _(filter test)_   |
| **20**   | **WMI Event Consumer Activity** | 🛠 _(consumer tool)_ |
| **21**   | **WMI Event Binding Activity**  | 🔗 _(binding link)_  |


💡 **Memory Trick:**  
- **1–7** 🖥 = Process & Image stuff.
- **8–10** 🛡 = Security & low-level access.
- **11–14** 📂 = File & Registry changes.
- **19–22** 🌐 = WMI & network queries.
---

