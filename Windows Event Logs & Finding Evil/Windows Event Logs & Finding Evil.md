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

| `Field`           | `What it Means`                                                |
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

```shell-session
xfreerdp /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /v:ip
/dynamic-resolution
```


#### question

1. Analyze the event with ID 4624, that took place on 8/3/2022 at 10:23:25. Conduct a similar investigation as outlined in this section and provide the name of the executable responsible for the modification of the auditing settings as your answer. Answer format: T_W_____.exe


![](../attachments/Pasted%20image%2020250809110718.png)

![](../attachments/Pasted%20image%2020250809111024.png)


![](../attachments/Pasted%20image%2020250809115147.png)


- **LogonType** = `5` → This means **Service logon** (SYSTEM account started a service).
- **ProcessName** = `C:\Windows\System32\services.exe` → This is the process that triggered the logon.
- **SubjectLogonId** and **TargetLogonId** = `0x3e7` → This is important for correlation.

![](../attachments/Pasted%20image%2020250809115426.png)


2.  Build an XML query to determine if the previously mentioned executable modified the auditing settings of C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF\wpfgfx_v0400.dll. Enter the time of the identified event in the format HH:MM:SS as your answer.

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4907) and TimeCreated[@SystemTime&gt;='2022-08-03T17:23:25.000Z' and @SystemTime&lt;='2022-08-03T17:24:00.999Z']]] and
    *[EventData[Data[@Name='ObjectName']='C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF\wpfgfx_v0400.dll']]</Select>
  </Query>
</QueryList>
```

![](../attachments/Pasted%20image%2020250809120110.png)


---
---

## Analyzing Evil With Sysmon & Event Logs

- **Sysmon** (_System Monitor_) is a **Windows system service** + **device driver** that    
    - Remains active across reboots.
    - Monitors & logs system activity to the **Windows Event Log**.
    - Helps with **deep monitoring** & **cyber forensic analysis**.
- **Purpose:** Provides detailed logs that the built-in Windows Security Log doesn’t record

**Sysmon Components**
1. windows service :runs in the background to monitor activity
2. device driver : assists in capturing system level data
3. event log : displays captured data in event viewer we can see that in 
`Applications and services logs > microsoft > windows > sysmon`

[full details](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

#### **Sysmon configuration** 
its a xml configuration file where we can include what kind of logs we need to include and what kind of logs we need to exclude 

 **SwiftOnSecurity Sysmon Config** – [https://github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
 (Comprehensive, widely used in SOCs.)

**Olaf Hartong Sysmon Modular** – [https://github.com/olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)  
(Modular approach – add only what you need.)

#### **Sysmon installation**

[full details](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

```
C:\Tools\Sysmon> sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n
```

`-i` install
`-accepteula` accept license automatically
`-h md5, sha256, imphash` log file hashes
`-l` log loading of modules
`-n` log network connections

```
sysmon.exe -c sysmonconfig-export.xml
```

loading the custom xml module 



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


#### Detection Example 1: Detecting DLL Hijacking

- we will use event type 7 used to load ddl or images
- so we need to modify the `sysmonconfig-export.xml`
- we change include to exclude 
- remember like we dont want to include the rules to load images we exclude every thing and collect all the logs
- then load the image 

```shell
xfreerdp /u:Administrator /p:'HTB_@cad3my_lab_W1n10_r00t!@0' /v:ip /dynamic-resolution
```


#### Questions
Replicate the DLL hijacking attack described in this section and provide the SHA256 hash of the malicious WININET.dll as your answer. "C:\Tools\Sysmon" and "C:\Tools\Reflective DLLInjection" on the spawned target contain everything you need.


![](../attachments/Pasted%20image%2020250809194448.png)

![](../attachments/Pasted%20image%2020250809194606.png)

With the modified Sysmon configuration, we can start observing image load events. To view these events, navigate to the Event Viewer and access "Applications and Services" -> "Microsoft" -> "Windows" -> "Sysmon."

[best blog that has DLL Hijacking ](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)

if we see `calc.exe` 
![](../attachments/Pasted%20image%2020250809195336.png)

[reflective DLL - a example that contain calc.exe and some dlls to test](https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master/bin).

we will take `calc.exe` and `WININET.dll` in the desktop folder and then we will run calc.exe it will load `WININET.dll` which is not in the windows core folder but which is in the desktop 
that dll contain a messabebox code that can be any malware 

![](../attachments/Pasted%20image%2020250809200809.png)

**Detection**

Event Viewer and access "Applications and Services" -> "Microsoft" -> "Windows" -> "Sysmon."

- add the filter event code 7

`idk why first i did not get the calc.exe and the win..dll so there was inject.exe and reflective_dll.dll so i use and done but i was not able to find the reflective_dll.dll with inject.exe`

`so idk i guess this is the right answer`
`51F2305DCF385056C68F7CCF5B1B3B9304865CEF1257947D4AD6EF5FAD2E3B13`

---
#### Detection Example 2: Detecting Unmanaged PowerShell/C-Sharp Injection

- C# is a managed language the code isnt executed directly by the cpu like odl-school c or assembly but run by a runtime environment deals with memory, security and garbage collector 
- the C# runtime is called as Common Language Runtime(CLR) a part of .net framework

##### how C# code will run
- .cs file 
- compiler (csc.exe) will convert the code to bytecode (intermediate language IL)
- if we run the bytecode loads IL which uses JIT compiler(just in time) this will we in the cpu instruction

##### why security folw
- Because C# needs the CLR, **malicious C# code also needs it** — if you can detect CLR activity in suspicious contexts, you might catch attacks like:
- **NET malware** (e.g., SharpHound, Covenant, PowerShell assemblies).    
    - **In-memory C# injection** (using `Assembly.Load` or reflective loading).
- This also means unusual loading of CLR DLLs (`clr.dll`, `mscorwks.dll`, `mscoree.dll`) in non-.NET processes can be a red flag.

in simple application that loads `CLR` that should be a `.NET` application if any application that is not .NET that is loading CLR that is bad

to detect C# injection we use  [Process Hacker](https://processhacker.sourceforge.io/).

```
The presence of "Microsoft .NET Runtime...", `clr.dll`, and `clrjit.dll` should attract our attention. These 2 DLLs are used when C# code is ran as part of the runtime to execute the bytecode.

Viewing modules shows `clr.dll and `clrjit.dll loaded — those are the .NET runtime DLLs.
```


#### powerhacker

| Color         | Meaning                                     |
| ------------- | ------------------------------------------- |
| 🟩 Green      | Managed (.NET) process — uses CLR runtime   |
| 🟪 Purple     | Windows Service                             |
| 🟦 Light Blue | Immersive app (Windows Store / UWP)         |
| 🔵 Dark Blue  | Suspended process                           |
| ⚪ White       | Normal unmanaged process                    |
| ⚫ Grey        | Terminated process remnant (zombie process) |
normal processes is converted into green this is suspicious  

To showcase unmanaged PowerShell injection, we can inject an [unmanaged PowerShell-like DLL](https://github.com/leechristensen/UnmanagedPowerShell) into a random process, such as `spoolsv.exe`. We can do that by utilizing the [PSInject project](https://github.com/EmpireProject/PSInject) in the following manner.

#### Question

 Replicate the Unmanaged PowerShell attack described in this section and provide the SHA256 hash of clrjit.dll that spoolsv.exe will load as your answer. "C:\Tools\Sysmon" and "C:\Tools\PSInject" on the spawned target contain everything you need.

**steps of attack**
- `spoolsv.exe` – the print spooler service
- inject a malicious powershell engin into it 

```powershell
powershell -ep bypass
 Import-Module .\Invoke-PSInject.ps1
 Invoke-PSInject -ProcId [Process ID of spoolsv.exe] -PoshCode "V3JpdGUtSG9zdCAiSGVsbG8sIEd1cnU5OSEi"
```

- `-ep bypass`  This allows you to run scripts even if your system policy is set to block them.
- This **loads a PowerShell script** (`Invoke-PSInject.ps1`) into the current session. Takes PowerShell code and executes it _inside_ another process (not powershell.exe itself
- **`-ProcId`** → tells PSInject which process to inject into. Here, it’s the Process ID of `spoolsv.exe`
- **`-PoshCode`** → this is the actual PowerShell code to run.
- **The string `"V3JpdGUtSG9zdCAiSGVsbG8sIEd1cnU5OSEi"`** is **Base64 encoded**. if we encode it will be `write-Host "hello, guru99!"`


`C:\Tools\processhacker\x64` run the processhacker application

![](../attachments/Pasted%20image%2020250809214416.png)


![](../attachments/Pasted%20image%2020250809214938.png)

see the color is changed and they are loaded the `clr.dll` and `cljt.dll` 

same we way we can detect using evnt id 7
8a3cd3cf2249e9971806b15c75a892e6a44cca5ff5ea5ca89fda951cd2c09aa9

#### Detection Example 3: Detecting Credential Dumping

- This **credential dumping** scenario is all about **stealing passwords directly from Windows memory**.
- **Target:** `lsass.exe` → This is a Windows system process that stores sensitive authentication info (password hashes, Kerberos tickets, etc.) in memory.
- **Tool Used:** **Mimikatz** → A very popular post-exploitation tool hackers use to read LSASS memory and extract credentials.

1. Attacker Gains Admin or SYSTEM Privileges
	1. Without elevated privileges, you can’t touch LSASS memory. `privilege::debug`
	2. This requests **SeDebugPrivilege** — a Windows permission that lets you debug or access other processes (like LSASS).
2. Attacker Reads LSASS Memory
	1. `sekurlsa::logonpasswords` connects to LSASS and dumps out any stored credentials.
	2. this will dump all the hashes
3. Attacker Uses Stolen Credentials

```
cd C:\Tools\Mimikatz
AgnetEXE
privilege::debug
sekurlsa::logonpasswords
```

#### How to Detect This

- sysmon event id 10 process access
- this tells us when one process tries to open another process's memory or handle.

#### question

Replicate the Credential Dumping attack described in this section and provide the NTLM hash of the Administrator user as your answer. "C:\Tools\Sysmon" and "C:\Tools\Mimikatz" on the spawned target contain everything you need.

![](../attachments/Pasted%20image%2020250809221107.png)

![](../attachments/Pasted%20image%2020250809222245.png)

----
---




### Event Tracing for Windows (ETW)

---

**What Is ETW?**
**Definition**:  
ETW (Event Tracing for Windows) is a high-speed, low-overhead tracing framework built into Windows OS that allows logging of detailed system and application events in real-time.
- Developed by Microsoft
- Works in both **user-mode** and **kernel-mode**
- Uses a **publish-subscribe model**

> **Think of ETW as a powerful microscope into the Windows OS internals** — capturing deep, real-time visibility of process, network, registry, and system behavior.

---

🔍 **Why ETW Matters in Security**
- Traditional logging (like Event Viewer) only scratches the surface.
- ETW gives **fine-grained**, **real-time**, and **low-noise** telemetry.
- It captures:
    - Process creation/termination
    - File access
    - Registry changes
    - Thread injections
    - DLL loads
    - Network connections
- Used by tools like **Sysmon**, **Windows Defender**, **WDAC**, **AMSI**, **ETW TI (Threat Intelligence)**.
---
**ETW Architecture & Components**

![](../attachments/Pasted%20image%2020250901235750.png)


  **Providers**
- Generate events.
- Examples: `Microsoft-Windows-Sysmon`, `Microsoft-Windows-Kernel-Process`, `Winlogon`, etc.
- Types:
    - **Manifest-based**
    - **MOF-based**
    - **WPP-based**   
    - **TraceLogging**

**Controllers**
- Start/Stop ETW sessions.
- Choose which providers and what level/keywords to log.
- Example tool: `logman.exe`

 **Consumers**
- Apps or services that **receive ETW data**.
- Examples: `eventvwr`, custom PowerShell scripts, SIEM agents, or custom tools.

 **Channels**
- Logical grouping of events (Admin, Operational, Debug, etc.)
- Only providers with a Channel property can be read in Event Viewer.

---

💡 How Does It Work?
- ETW operates via **Trace Sessions** (a kind of buffer).
- Controllers configure sessions.
- Providers write events to sessions.
- Consumers pull data from sessions or `.etl` (Event Trace Log) files.
---
 ⚒️ Interacting with ETW using `logman`
 
> `logman` = CLI tool to manage ETW sessions


#### Common Use Cases:

|Command|What it Does|
|---|---|
|`logman query -ets`|List all live ETW sessions|
|`logman query "SessionName" -ets`|View providers & details of a specific session|
|`logman query providers`|List all providers on system|
|`logman query providers <Name>`|View levels/keywords supported by a specific provider|
|`logman start myTrace -p <ProviderName>`|Start your own custom trace session|

Key Flags:

- `-ets` → required for querying **real-time/live** system-wide ETW sessions
- `findstr` → used to filter huge lists (`| findstr "Sysmon"`)

---

#### 📦 Sysmon & ETW

- **Sysmon** is an ETW provider (event source) and consumer (writes to Windows Event Logs).
- Events like **Event ID 10 (Process Access)** are sourced from ETW and need to be **enabled in the Sysmon config**.
- Using ETW directly lets you go **beyond what Sysmon collects**.

---

Notes & Tips
- ETW logs are often saved as `.etl` files for offline analysis.
- Use `Get-WinEvent` or custom tools to parse `.etl` logs.
- High-volume providers are **disabled by default** to prevent performance impact
- ETW is a **lightweight** and **real-time friendly** telemetry source.

---
#### GUI tool for ETW

**Performance Monitor**
- View active trace sessions.
- See providers attached to those sessions.
- Modify sessions by adding/removing providers.
- Create your own sessions (under **User Defined**).


**EtwExplorer**
- A third-party GUI tool to browse ETW providers and metadata.
- Helps in exploring what each provider supports (keywords, levels, GUIDs, etc.).


- **Providers** are components (from Windows or third-party apps) that **generate ETW events**.
- Each provider has:
    - A unique **name or GUID**.
    - Event **Levels** (Critical, Error, Warning, Info, Verbose).
    - **Keywords** to filter specific event types.
- Windows 10+ has over **1,000 built-in providers**.


#### 🔎 Useful ETW Providers for Security & Detection

|**Provider**|**Use Case**|
|---|---|
|`Microsoft-Windows-Kernel-Process`|Process injection, hollowing, suspicious execution|
|`Microsoft-Windows-Kernel-File`|File access, modification, ransomware activity|
|`Microsoft-Windows-Kernel-Network`|C2 activity, unauthorized connections, data exfil|
|`Microsoft-Windows-SMBClient/Server`|Lateral movement, suspicious file shares|
|`Microsoft-Windows-DotNETRuntime`|.NET exploitation, malicious .NET assemblies|
|`OpenSSH`|Brute force, SSH logins, failed/success attempts|
|`Microsoft-Windows-VPN-Client`|VPN activity (authorized/unauthorized access)|
|`Microsoft-Windows-PowerShell`|Suspicious script execution, script block logging|
|`Microsoft-Windows-Kernel-Registry`|Registry changes (often used for persistence)|
|`Microsoft-Windows-CodeIntegrity`|Malicious drivers, unsigned code loading|
|`Microsoft-Antimalware-Service`|Disabled AV, evasion of AV controls|
|`WinRM`|Remote command execution, lateral movement|
|`Microsoft-Windows-TerminalServices-LocalSessionManager`|Remote desktop connections|
|`Microsoft-Windows-Security-Mitigations`|Bypass of security controls (e.g., DEP, ASLR)|
|`Microsoft-Windows-DNS-Client`|DNS tunneling, weird DNS queries|
|`Microsoft-Antimalware-Protection`|Protection status, evasion detection|

#### 🔐 Restricted Providers (Privileged Access Required)

Example: `Microsoft-Windows-Threat-Intelligence`
- Only accessible by processes with **PPL (Protected Process Light)** rights.
- Used by **EDRs and AV tools** to get deep telemetry (e.g., Defender ATP).
- Cannot be accessed by normal tools or users (unless elevated via tricks or approved by Microsoft).
**Why it's restricted**: To prevent abuse by malware (since it has deep access to threat data).
To access it, a vendor must:
- Register with Microsoft.
- Implement **ELAM** driver (Early Launch Anti-Malware).
- Pass strict validation and sign with Microsoft-issued certificates.

```
sysmon is great but doesnt capture everything like some low level kernel events

logs are collected by .etl file
```

**References**
- [Medium Article on ETW](https://nasbench.medium.com/a-primer-on-event-tracing-for-windows-etw-997725c082bf)
- [Beginner’s ETW Guide – bmcder.com](https://bmcder.com/blog/a-begginers-all-inclusive-guide-to-etw)

---
---

## Tapping into ETW

### Detection Example 1: Detecting Strange Parent-Child Relationships

its when a process is calling child process 
ex: calc.exe is spawning "cmd.exe"

![](../attachments/Pasted%20image%2020250902000352.png)

**Parent PID Spoofing** can be executed through the [psgetsystem project](https://github.com/decoder-it/psgetsystem) in the following manner.

```powershell
PS C:\Tools\psgetsystem> powershell -ep bypass

PS C:\Tools\psgetsystem> Import-Module .\psgetsys.ps1 

PS C:\Tools\psgetsystem> [MyProcess]::CreateProcessFromParent([Process ID of spoolsv.exe],"C:\Windows\System32\cmd.exe","")

```

![[Pasted image 20250902002403.png]]

![[Pasted image 20250902002729.png]]



Due to the parent PID spoofing technique we employed, Sysmon Event 1 incorrectly displays `spoolsv.exe` as the parent of `cmd.exe`. However, it was actually `powershell.exe` that created `cmd.exe`.


 Let's begin by collecting data from the `Microsoft-Windows-Kernel-Process` provider using [SilkETW](https://github.com/mandiant/SilkETW) (the provider can be identified using `logman` as we described previously, `logman.exe query providers | findstr "Process"`). After that, we can proceed to simulate the attack again to assess whether ETW can provide us with more accurate information regarding the execution of `cmd.exe`.

```powershell
c:\Tools\SilkETW_SilkService_v8\v8\SilkETW>SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\windows\temp\etw.json

```




The `etw.json` file (that includes data from the `Microsoft-Windows-Kernel-Process` provider) seems to contain information about `powershell.exe` being the one who created `cmd.exe`.

It should be noted that SilkETW event logs can be ingested and viewed by Windows Event Viewer through `SilkService` to provide us with deeper and more extensive visibility into the actions performed on a system.

### Detection Example 2: Detecting Malicious .NET Assembly Loading

