## Introduction and terminology

#### Active Directory 
- AD is like a phonebook + security guard of a company's IT env
- it's directory service that stores info about users, computers, printers and groups
- its centralized management system for authentication, authorization and accounting 
- If attackers hack AD → they can control **all users, all computers, all data** in the organization.  
- many hackers dont need new vulnerabilities they exploit misconfigurations and features that admins often overlook
- [extra resources](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)

|Term|Meaning|Example|
|---|---|---|
|**Domain**|A group of objects (users, devices) that share the same AD database.|`company.local`|
|**Tree**|One or more domains grouped together.|`sales.company.local`, `hr.company.local` under `company.local`|
|**Forest**|A collection of trees (topmost level).|`company.local` + `partner.local` in same forest|
|**OU (Organizational Unit)**|A container for users, computers, or other OUs.|`OU=HR, OU=Finance`|
|**Trust**|A relationship allowing access between domains.|HR domain trusts Finance domain so HR users can access finance apps|
|**Domain Controller (DC)**|A server that runs AD and handles authentication & authorization.|Like the "gatekeeper"|
|**AD Data Store**|Stores AD database (`NTDS.DIT` file).|Located in `%SystemRoot%\NTDS`|
[Audit logon events](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-logon-events)

|Port|Service|
|---|---|
|53|DNS|
|88|Kerberos|
|135|RPC/WMI|
|137–139, 445|SMB|
|389, 636|LDAP|
|3389|RDP|
|5985, 5986|WinRM (PowerShell Remoting)|

---
## Overview and lab env

The assumption is that an attacker has already gained remote code execution (of some sort) on that Windows 10 (WS001) machine. The user, which we assume is compromised, is `Bob`, a regular user in Active Directory with no special permissions assigned.

The environment consists of the following machines and their corresponding IP addresses:

- `DC1`: `172.16.18.3`
- `DC2`: `172.16.18.4`
- `Server01`: `172.16.18.10`
- `PKI`: `172.16.18.15`
- `WS001`: `DHCP or 172.16.18.25` (depending on the section)
- `Kali Linux`: `DHCP or 172.16.18.20` (depending on the section)

### Connect to WS001 via RDP

```shell
xfreerdp /u:eagle\\bob /p:Slavi123 /v:10.129.108.202 /dynamic-resolution
```

### Transfer the files

![](attachments/Pasted%20image%2020250818123430.png)

To access the folder from the Kali machine, you can use the 'smbclient' command. Accessing the folder requires authentication, so you will need to provide credentials. The command can be executed with the Administrator account as follows:

```shell
smbclient \\\\TARGET_IP\\Share -U eagle/administrator%Slavi123
```

![](attachments/Pasted%20image%2020250818123709.png)

---

## kerberoasting 

![](attachments/Pasted%20image%2020250819060324.png)

TGT- encrypted ticket (this user is authenticated.)
token (service token) is when we request access to a specific service 

Attackers: grab those tickets → crack them offline → get the **service account password**.
In AD, [Service Principal Name (SPN)](https://learn.microsoft.com/en-us/windows/win32/ad/service-principal-names) = tells Kerberos which account runs a service. (AS)

- **AES** → strong, slow to brute-force → attacker needs a lot more time.
- **RC4** → weaker, very fast to brute-force → attacker prefers this.
- **DES** → ancient, almost useless, but sometimes still enabled for legacy apps.
But attackers can **force a downgrade** (e.g., request RC4 instead of AES) if the environment still allows it.
That **Service Ticket** is encrypted with the **service account’s NTLM hash** (derived from its password).

### ATTACK

 [Rubeus](https://github.com/GhostPack/Rubeus) is the tool that we are using . this tool is used to fuck with AD env and perform many attacks
```powershell
PS C:\Users\bob\Downloads> .\Rubeus.exe kerberoast /outfile:spn.txt
```

