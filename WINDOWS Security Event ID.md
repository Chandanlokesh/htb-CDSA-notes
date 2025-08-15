### logon & logoff events

|Event ID|Emoji|Name|Why It Matters / When to Hunt|
|---|---|---|---|
|**4608**|🔄|Windows Startup|Good timeline anchor when system boots.|
|**4609**|🔃|Windows Shutdown|Capture unexpected shutdowns.|
|**4624**|🔑|Successful Logon|Look for logins at odd hours or from unexpected users.|
|**4625**|🚫|Failed Logon|Spike in failures may signal brute-force attempts. ([Graylog](https://graylog.org/post/critical-windows-event-ids-to-monitor/?utm_source=chatgpt.com "Critical Windows Event ID's to Monitor"), [SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|
|**4634**|🚪|Logoff|Identify short-lived sessions or stealthy logouts. ([Graylog](https://graylog.org/post/critical-windows-event-ids-to-monitor/?utm_source=chatgpt.com "Critical Windows Event ID's to Monitor"))|
|**4647**|✋|User Initiated Logoff|Correlate with logout behavior in hunts. ([Graylog](https://graylog.org/post/critical-windows-event-ids-to-monitor/?utm_source=chatgpt.com "Critical Windows Event ID's to Monitor"))|
|**4648**|👤➡️💻|Logon with Explicit Credentials|Red flags lateral movement. ([Graylog](https://graylog.org/post/critical-windows-event-ids-to-monitor/?utm_source=chatgpt.com "Critical Windows Event ID's to Monitor"), [SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|
|**4778**|🔄|Session Reconnected to Winstation|Detect remote reconnections. ([SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|
|**4779**|⏸️|Session Disconnected from Winstation|Check for dropped RDP sessions. ([Graylog](https://graylog.org/post/critical-windows-event-ids-to-monitor/?utm_source=chatgpt.com "Critical Windows Event ID's to Monitor"), [SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|
|**4800**|🔒|Workstation Locked|Useful for timing activity. ([SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|
|**4801**|🔓|Workstation Unlocked|Track user or attacker activity post-lock. ([SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|

### Account & Group Management

|Event ID|Emoji|Name|Why It Matters|
|---|---|---|---|
|**4720**|➕👤|User Account Created|Detect rogue accounts. ([SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|
|**4722**|🔓|User Account Enabled|Attackers may re-enable disabled accounts.|
|**4724**|🔑|Attempted Password Reset|Could signal credential takeover. ([Gist](https://gist.github.com/githubfoam/69eee155e4edafb2e679fb6ac5ea47d0?utm_source=chatgpt.com "windows event logs cheat sheet"))|
|**4728**|👥|Member Added to Global Group|Look for unauthorized privilege escalations. ([download.manageengine.com](https://download.manageengine.com/products/active-directory-audit/the-eight-most-critical-windows-event-ids.pdf?utm_source=chatgpt.com "The 8 most critical Windows security event IDs"))|
|**4732**|🛡️|Member Added to Local Group|Check for additions to “Administrators” etc. ([download.manageengine.com](https://download.manageengine.com/products/active-directory-audit/the-eight-most-critical-windows-event-ids.pdf?utm_source=chatgpt.com "The 8 most critical Windows security event IDs"), [SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|
|**4738**|✏️|User Account Changed|May indicate stealthy permission changes. ([Gist](https://gist.github.com/githubfoam/69eee155e4edafb2e679fb6ac5ea47d0?utm_source=chatgpt.com "windows event logs cheat sheet"))|
|**4740**|⛔|Account Locked Out|Brute-force indicator. ([SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|

### Policy, Audit & Security Monitoring

|Event ID|Emoji|Name|Why It Matters|
|---|---|---|---|
|**4719**|📋|Audit Policy Changed|Could signal logging tampering. ([Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor?utm_source=chatgpt.com "Appendix L - Events to Monitor"), [Azure Documentation](https://docs.azure.cn/en-us/sentinel/windows-security-event-id-reference?utm_source=chatgpt.com "Windows security event sets that can be sent to Microsoft ..."))|
|**1102**|🧹|Audit Log Cleared|High-severity—often to cover intrusion traces. ([Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor?utm_source=chatgpt.com "Appendix L - Events to Monitor"), [download.manageengine.com](https://download.manageengine.com/products/active-directory-audit/the-eight-most-critical-windows-event-ids.pdf?utm_source=chatgpt.com "The 8 most critical Windows security event IDs"))|
|**4649**|🔁|Replay Attack Detected|May indicate credential spoofing attacks. ([Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor?utm_source=chatgpt.com "Appendix L - Events to Monitor"))|

### Scheduled Tasks & Services

|Event ID|Emoji|Name|Why It Matters|
|---|---|---|---|
|**4698**|⏰|Scheduled Task Created|Persistence indicator. ([SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|
|**4700 / 4701**|🔄⏰|Task Enabled / Disabled|Attackers manipulate scheduled jobs. ([SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|
|**4702**|✏️⏰|Scheduled Task Updated|Check for tampered legitimate tasks. ([SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|
|**4697**|🛠️|Service Installed|Could mark service-based malware. ([SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))|
|**7045**|🛠️📦|Service Installed (System Log)|Cross-check with security events. ([Gist](https://gist.github.com/githubfoam/69eee155e4edafb2e679fb6ac5ea47d0?utm_source=chatgpt.com "windows event logs cheat sheet"))|

### Object & Share Access

|Event ID|Emoji|Name|Why It Matters|
|---|---|---|---|
|**4656**|📂|Handle to Object Requested|Access to sensitive objects.|
|**5140**|📂🌐|Network Share Accessed|Possible data theft. ([Gist](https://gist.github.com/githubfoam/69eee155e4edafb2e679fb6ac5ea47d0?utm_source=chatgpt.com "windows event logs cheat sheet"), [Azure Documentation](https://docs.azure.cn/en-us/sentinel/windows-security-event-id-reference?utm_source=chatgpt.com "Windows security event sets that can be sent to Microsoft ..."))|
|**5142**|➕🌐|Network Share Created|May indicate staging for exfiltration.|
|**5145**|🔍🌐|Network Share Access Check|Recon from attacker.|
|**5157**|🚫🌐|Connection Blocked (WFP)|Windows Firewall blocked suspicious traffic.|
### Legacy & Other Useful Events

| Event ID | Emoji | Name                        | Why It Matters                                                                                                                                                                                                                                                                                                          |
| -------- | ----- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **4616** | ⏱     | System Time Changed         | Attackers may change time to disturb timelines. ([SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))                                                                                                                                                                  |
| **4614** | ⚙️    | Notification Package Loaded | Detects when authentication packages are loaded. ([SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs."))                                                                                                                                                                 |
| **4621** | 🆘    | CrashOnAuditFail Recovered  | Security was compromised at boot. ([Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor?utm_source=chatgpt.com "Appendix L - Events to Monitor"), [SS64](https://ss64.com/ps/syntax-eventids.html?utm_source=chatgpt.com "List of Windows Event IDs.")) |
| **4649** | 🔁    | Replay Attack Detected      | Possible attempt at credential reuse.                                                                                                                                                                                                                                                                                   |