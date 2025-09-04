
## Intrusion detection with splunk (real world scenario)

















---
---

## Intrusion Detection With Splunk Based On TTPs

- the first approach is playing a game of `spot the known`.
- The second approach, `while still informed by an understanding of attacker TTPs`, leans heavily on statistical analysis and anomaly detection to identify abnormal behavior within the sea of normal activity. This strategy is more of a game of `spot the unusual`.
- `the key is to understand our data and environment, then carefully tune our queries and thresholds to balance the need for accurate detection with the desire to avoid false positives`.

### Detection of Reconnaissance Activities leveraging native windows binaries 

attackers are using the built in tools to gather information from the internal tools
- **System info** → `systeminfo`, `hostname`, `tasklist`
- **User info** → `net user`, `whoami /all`, `net localgroup administrators`
- **Domain info** → `net group /domain`, `nltest /dclist`, `dsquery`
- **Network info** → `ipconfig /all`, `arp -a`, `netstat -ano`
- **Shares & services** → `net share`, `sc query`

example: `net.exe` → enumerate users, groups, shares

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 Image=*\\ipconfig.exe OR Image=*\\net.exe OR Image=*\\whoami.exe OR Image=*\\netstat.exe OR Image=*\\nbtstat.exe OR Image=*\\hostname.exe OR Image=*\\tasklist.exe | stats count by Image,CommandLine | sort - count
```

### Detection Of Requesting Malicious Payloads/Tools Hosted On Reputable/Whitelisted Domains (Such As githubusercontent.com)

It means watching for when attackers try to **download malware from trusted websites (like GitHub)** to avoid being blocked, and creating alerts for that activity.

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=22  QueryName="*github*" | stats count by Image, QueryName
```

### Detection Of PsExec Usage

- PsExec = **legit admin tool** from **Sysinternals suite**.
- Used by IT admins to run commands **remotely** on Windows machines.
- Needs **Local Administrator** rights.
`psexec \\target cmd.exe` will open remote shell on another machine

attackers use [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) which is a  [Windows Sysinternals](https://learn.microsoft.com/en-us/sysinternals/) tool which can be used for lateral movement once they compromised one system and want to spread . instead of malware they use PsExec 

Several MITRE ATT&CK techniques, including `T1569.002 (System Services: Service Execution)`, `T1021.002 (Remote Services: SMB/Windows Admin Shares)`, and `T1570 (Lateral Tool Transfer)`, have seen PsExec in play.

this is how the PsExec works

| **Step** | **Activity**                      | **What PsExec Actually Does**                                                                             | **Sysmon/Windows Events to Monitor**                                                                                                                                | **Detection/Notes**                                                                                             |
| -------- | --------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **1**    | **Network logon**                 | PsExec authenticates to target via **SMB** using provided creds (admin required).                         | - **Windows 4624 (Logon)** → Type 3 (network)- **Windows 4625** (failed logon, if bad creds)                                                                        | Look for unusual admin logons from non-admin machines (e.g., user workstation logging in as domain admin).      |
| **2**    | **Copy `PSEXESVC.exe` to Admin$** | PsExec drops its service binary into the hidden admin share `\\Target\Admin$\PSEXESVC.exe`.               | - **Sysmon 11 (File Create)** → File path: `C:\Windows\PSEXESVC.exe`                                                                                                | This file is a strong PsExec indicator. Legit admin tools rarely drop executables into Admin$.                  |
| **3**    | **Service installed**             | PsExec registers a service **PSEXESVC** using Service Control Manager (SCM).                              | - **Sysmon 13 (Registry Set)** → Registry path: `HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC`- **Windows 7045 (Service Installed)** → Service name = `PSEXESVC` | Look for service creation events with suspicious names (`PSEXESVC`). Rare in normal environments.               |
| **4**    | **Named pipe communications**     | PsExec sets up a **named pipe** (`\PSEXESVC`) to communicate between attacker and target.                 | - **Sysmon 17 (Pipe Created)** → Pipe name: `\PSEXESVC`- **Sysmon 18 (Pipe Connected)** → Client connects to pipe                                                   | Named pipes are strong PsExec signatures. Look for unusual named pipes created by `services.exe`.               |
| **5**    | **Remote process execution**      | The service executes requested commands (e.g., `cmd.exe`, `ipconfig`, `powershell.exe`) under **SYSTEM**. | - **Sysmon 1 (Process Creation)** → Parent = `PSEXESVC.exe`, Child = attacker-specified process                                                                     | Look for processes spawned by `PSEXESVC.exe`. Example: SYSTEM → cmd.exe or powershell.exe with suspicious args. |
| **6**    | **Cleanup**                       | PsExec stops & deletes the service, removes `PSEXESVC.exe` (sometimes fails, leaving artifacts).          | - **Sysmon 11 (File Delete / Write)** if monitored- Registry remnants under `Services\PSEXESVC`                                                                     | Sometimes `PSEXESVC.exe` remains if cleanup fails. That’s a great forensic artifact.                            |

**Case 1: Leveraging Sysmon Event ID 13**

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath" | rex field=Details "(?<reg_file_name>[^\\\]+)$" | eval reg_file_name = lower(reg_file_name), file_name = if(isnull(file_name),reg_file_name,lower(file_name)) | stats values(Image) AS Image, values(Details) AS RegistryDetails, values(_time) AS EventTimes, count by file_name, ComputerName
```

Among the `less frequent` search results, it is evident that there are indications of execution resembling PsExec.

**Case 2: Leveraging Sysmon Event ID 11**

“Show me a summary of all files created or modified by the Windows `System` process, along with a count of how many times each file was created.”
```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image=System | stats count by TargetFilename
```

less frequent

**Case 3: Leveraging Sysmon Event ID 18**

this is used to make a C2

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=18 Image=System | stats count by PipeName
```

### Detection of utilizing archive files for transferring tools or data exfiltration

 `zip`, `rar`, or `7z` files for transferring tools to a compromised host or exfiltrating data from it

```shell
index="main" EventCode=11 (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z") | stats count by ComputerName, User, TargetFilename | sort - count
```

### Detection Of Utilizing PowerShell or MS Edge For Downloading Payloads/Tools

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*powershell.exe*" |  stats count by Image, TargetFilename |  sort + count
```

The `*Zone.Identifier` is indicative of a file downloaded from the internet or another potentially untrustworthy source. Windows uses this zone identifier to track the security zones of a file. The `Zone.Identifier` is an ADS (Alternate Data Stream) that contains metadata about where the file was downloaded from and its security settings.

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*msedge.exe" TargetFilename=*"Zone.Identifier" |  stats count by TargetFilename |  sort + count
```

### Detection of execution form atypical or suspicious locations

programs that start (execute) from directories where normal trusted programs usually dont live

If you suddenly see an `.exe` or `.dll` running from places like:
- `C:\Users\<username>\AppData\Local\Temp\`
- `C:\Users\Public\`
- `C:\Windows\Temp\`
- Desktop or Downloads folders

```shell
index="main" EventCode=1 | regex Image="C:\\\\Users\\\\.*\\\\Downloads\\\\.*" |  stats count by Image
```

### Detection Of Executables or DLLs Being Created Outside The Windows Directory

```shell
index="main" EventCode=11 (TargetFilename="*.exe" OR TargetFilename="*.dll") TargetFilename!="*\\windows\\*" | stats count by User, TargetFilename | sort + count
```

### Detection Of Misspelling Legitimate Binaries

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (CommandLine="*psexe*.exe" NOT (CommandLine="*PSEXESVC.exe" OR CommandLine="*PsExec64.exe")) OR (ParentCommandLine="*psexe*.exe" NOT (ParentCommandLine="*PSEXESVC.exe" OR ParentCommandLine="*PsExec64.exe")) OR (ParentImage="*psexe*.exe" NOT (ParentImage="*PSEXESVC.exe" OR ParentImage="*PsExec64.exe")) OR (Image="*psexe*.exe" NOT (Image="*PSEXESVC.exe" OR Image="*PsExec64.exe")) |  table Image, CommandLine, ParentImage, ParentCommandLine
```

### Detection Of Using Non-standard Ports For Communications/Transfers

```shell
index="main" EventCode=3 NOT (DestinationPort=80 OR DestinationPort=443 OR DestinationPort=22 OR DestinationPort=21) | stats count by SourceIp, DestinationIp, DestinationPort | sort - count
```

### question

Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the password utilized during the PsExec activity. Enter it as your answer.

`index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 CommandLine="*psexec*"`

in that see CommandLine field 

---
---

## Detecting Attacker Behavior with splunk based on analytics

Instead of rules, watch for **unusual behavior** compared to what’s normal

`streamstats` is a Splunk command that calculates **running totals, averages, counts, or time differences** across events in a stream.

Instead of only hunting for specific bad tools, you can let Splunk watch for **weird spikes or changes in behavior**.  
For example, if `notepad.exe` suddenly opens 200 network connections, Splunk can flag that. This is done with statistical tools like `streamstats`.

### Example

- look at sysmon eventid 3 for network connecton
- group events into hourly buckets "like for every process count many network connections it made in each 1-hour window"
- for each process calculate a running avg and standard deviation of network connections over last 24 
- If a process makes significantly more network connections than usual (over average + half a standard deviation), mark it as an **outlier**.
- Show only suspicious activity

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | bin _time span=1h | stats count as NetworkConnections by _time, Image | streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image | eval isOutlier=if(NetworkConnections > (avg + (0.5*stdev)), 1, 0) | search isOutlier=1
```


### Detection Of Abnormally Long Commands

```shell
index="main" sourcetype="WinEventLog:Sysmon" Image=*cmd.exe | eval len=len(CommandLine) | table User, len, CommandLine | sort - len
```

```shell
index="main" sourcetype="WinEventLog:Sysmon" Image=*cmd.exe ParentImage!="*msiexec.exe" ParentImage!="*explorer.exe" | eval len=len(CommandLine) | table User, len, CommandLine | sort - len
```

### Detection of abnormal cmd.exe activity

uses bucket concept

```shell
index="main" EventCode=1 (CommandLine="*cmd.exe*") | bucket _time span=1h | stats count as cmdCount by _time User CommandLine | eventstats avg(cmdCount) as avg stdev(cmdCount) as stdev | eval isOutlier=if(cmdCount > avg+1.5*stdev, 1, 0) | search isOutlier=1
```

### Detection Of Processes Loading A High Number Of DLLs In A Specific Time

show me the image that is loading more then 3 distinct in one hour of time 

```shell
index="main" EventCode=7 | bucket _time span=1h | stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image | where unique_dlls_loaded > 3 | stats count by Image, unique_dlls_loaded
```

next they are using some patterns to filter out like bunch of paths that should ignore , then one hour group next count unique dll per process and the number of dll (threshold) then summarize it

```shell
index="main" EventCode=7 NOT (Image="C:\\Windows\\System32*") NOT (Image="C:\\Program Files (x86)*") NOT (Image="C:\\Program Files*") NOT (Image="C:\\ProgramData*") NOT (Image="C:\\Users\\waldo\\AppData*")| bucket _time span=1h | stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image | where unique_dlls_loaded > 3 | stats count by Image, unique_dlls_loaded | sort - unique_dlls_loaded
```

### Detection Of Transactions Where The Same Process Has Been Created More Than Once On The Same Computer

Look at all processes on each computer. If the same process runs more than once, record it along with what started it, and count how often it happened. This can help identify suspicious repeated executions, which might indicate malware or scripts running in the background.

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | transaction ComputerName, Image | where mvcount(ProcessGuid) > 1 | stats count by Image, ParentImage
```

`rundll32.exe` and `svchost.exe` has some kind of more count

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1  | transaction ComputerName, Image  | where mvcount(ProcessGuid) > 1 | search Image="C:\\Windows\\System32\\rundll32.exe" ParentImage="C:\\Windows\\System32\\svchost.exe" | table CommandLine, ParentCommandLine
```

### question

Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through an analytics-driven SPL search against all data the source process images that are creating an unusually high number of threads in other processes. Enter the outlier process name as your answer where the number of injected threads is greater than two standard deviations above the average. Answer format: _.exe

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=8
| bin _time span=1h
| stats count as ThreadsInjected by SourceImage, TargetImage, _time
| stats avg(ThreadsInjected) as avgThreads stdev(ThreadsInjected) as sdThreads by SourceImage
```

---
---
