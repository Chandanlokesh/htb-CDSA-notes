
|**Event ID**|**Name**|**Explanation**|**When to Hunt / Example**|
|---|---|---|---|
|**1** 🛠️|Process Creation|Logs every new process created on the system, including parent/child relationships, command line, hashes.|Hunt for suspicious tools (`mimikatz.exe`), LOLBins (`powershell.exe -enc`), malware execution from temp folders.|
|**2** 🗑️|File Creation Time Changed|Logs changes to file creation timestamps (timestomping).|Check for attackers modifying timestamps to evade detection (`cmd.exe /c copy /b file` tricks).|
|**3** 🌐|Network Connection|Logs outbound TCP/UDP connections from a process, including IPs, ports, domains.|Hunt for C2 traffic from unusual processes (`notepad.exe` making HTTP requests).|
|**4** 📦|Sysmon Service State Changed|Logs when the Sysmon service is installed, stopped, or updated.|Hunt for attempts to disable monitoring before an attack.|
|**5** 📄|Process Terminated|Logs when a process ends.|Rarely used for detection alone; useful in correlation (e.g., short-lived suspicious processes).|
|**6** 🔄|Driver Loaded|Logs kernel-mode driver loading.|Check for unsigned or suspicious drivers (rootkits).|
|**7** 🧩|Image Loaded (DLL)|Logs DLLs loaded into a process.|Hunt for malicious DLL injection or LOLBin DLLs (`rundll32.exe`).|
|**8** 🔐|CreateRemoteThread|Logs threads created in another process (code injection).|Check for process injection techniques (`powershell.exe` injecting into `explorer.exe`).|
|**9** 🧠|RawAccessRead|Logs processes reading raw disk sectors (bypassing filesystem).|Hunt for disk forensic evasion or credential dumping tools.|
|**10** 🖇️|ProcessAccess|Logs processes accessing memory of another process.|Check for credential dumping (`lsass.exe` access).|
|**11** 📥|File Create|Logs newly created files.|Hunt for dropped malware payloads in suspicious directories (`C:\Users\Public\`).|
|**12** 📂|Registry Object Created|Logs registry keys created.|Look for persistence keys (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).|
|**13** 📝|Registry Value Set|Logs registry values changed.|Hunt for changes to `Run` keys or disabling security tools.|
|**14** 🗑️|Registry Value Deleted|Logs deleted registry values.|Hunt for removal of forensic evidence.|
|**15** 🔍|FileStream Created|Logs creation of alternate data streams (ADS).|Check for hidden malicious code stored in ADS.|
|**16** ⚙️|Sysmon Config Change|Logs changes to Sysmon configuration.|Detect attempts to weaken logging.|
|**17** 🔄|Named Pipe Created|Logs new named pipes (IPC).|Hunt for named pipes used by malware for interprocess comms.|
|**18** 🔌|Named Pipe Connected|Logs connections to named pipes.|Check for malware C2 over named pipes.|
|**19** 📦|WMI Event Filter|Logs creation of WMI event filters.|Hunt for WMI persistence (`SELECT * FROM __InstanceModificationEvent`).|
|**20** 🛠️|WMI Event Consumer|Logs creation of WMI consumers.|Check for malicious WMI payloads.|
|**21** 🔗|WMI Event Binding|Logs binding between WMI filter and consumer.|Hunt for full WMI persistence chains.|
|**22** 🌍|DNS Query|Logs DNS requests from a process.|Hunt for suspicious domains (`xyz123abc.com`) queried by system processes.|
|**23** 📡|File Delete (Archived)|Logs file deletions (archived in Sysmon config).|Hunt for removal of dropped malware.|
|**24** 🛡️|Clipboard Change|Logs changes to clipboard content.|Rare; could indicate data theft via clipboard monitoring.|
|**25** 💉|Process Tampering|Logs process hollowing, image replacement, or other tampering.|Hunt for malware injecting into legitimate processes.|
|**26** 🔒|File Delete (Logged)|Logs file deletions (without archive).|Hunt for attackers cleaning up tools after use.|