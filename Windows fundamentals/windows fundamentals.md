

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