
## 🗂 **Core ELK Fields for Threat Hunting**

_(These are common whether you’re looking at Sysmon, Security, or other log types — names might vary slightly depending on your ingest pipeline like Winlogbeat or Elastic Agent.)_

| Field Name                           | Emoji | Why it Matters                                                                          |
| ------------------------------------ | ----- | --------------------------------------------------------------------------------------- |
| **@timestamp**                       | ⏱️    | Time of the event — always key for timelines.                                           |
| **event.code**                       | 🆔    | Event ID (e.g., `4624`, `1` for Sysmon) — main filter for hunt queries.                 |
| **event.action**                     | 🎯    | Short description of what happened (depends on data source).                            |
| **winlog.event_id**                  | 🆔    | Same as `event.code` but in Winlogbeat mapping.                                         |
| **winlog.channel**                   | 📺    | Log source (Security, Microsoft-Windows-Sysmon/Operational, etc.).                      |
| **host.name** / **host.hostname**    | 💻    | Machine where the event happened.                                                       |
| **host.ip**                          | 🌐    | Host IP address.                                                                        |
| **user.name** / **winlog.user.name** | 👤    | Username involved in the event.                                                         |
| **user.domain**                      | 🏢    | Domain/Workgroup of the user.                                                           |
| **process.name**                     | ⚙️    | The process filename (e.g., `powershell.exe`).                                          |
| **process.executable**               | 📂    | Full path of the process (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`). |
| **process.command_line**             | 💬    | The exact command run — crucial for detecting malicious patterns.                       |
| **process.parent.name**              | 🧬    | Parent process — useful to spot suspicious process chains.                              |
| **process.parent.command_line**      | 🧬💬  | Command line of the parent process.                                                     |
| **file.name**                        | 📄    | File involved in the event (dropper, script, etc.).                                     |
| **file.path**                        | 📂    | Full file path.                                                                         |
| **hash.sha256 / hash.md5**           | 🔑    | File hashes for malware lookup.                                                         |
| **destination.ip**                   | 🌍    | Remote IP being connected to.                                                           |
| **destination.port**                 | 🚪    | Remote port number.                                                                     |
| **destination.domain**               | 🌐    | Remote domain/hostname.                                                                 |
| **source.ip**                        | 🏠    | Local IP initiating the connection.                                                     |
| **source.port**                      | 🔌    | Local port used.                                                                        |
| **registry.key**                     | 🔑📜  | Registry key accessed/modified.                                                         |
| **registry.value**                   | 📝    | Registry value data.                                                                    |
| **dns.question.name**                | ❓🌐   | Domain name requested in DNS query.                                                     |
| **network.protocol**                 | 📡    | Network protocol (TCP, UDP, HTTP, etc.).                                                |