
![ad](../attachments/Pasted%20image%2020250828105434.png)

**Active Directory (AD)** is a centralized directory service for Windows networks that stores identities (users/computers/groups) and policies, and provides authentication/authorization so admins can manage access across an organisation from one place.

**Why AD is attractive to attackers**
- control AD == control the network
- There have been many high-impact vulnerabilities and misconfigurations (your text mentioned examples like **Zerologon**, **PrintNightmare**, **noPac**) that allow privilege escalation or lateral movement.

### Defensive controls & hardening (practical list)

- **Least privilege**: only give admin rights when necessary. Separate accounts for admin tasks (no day-to-day admin work with domain admin).
    
- **Tiered administrative model** (separate accounts/systems for user, admin, domain admin roles).
    
- **Patching & inventory**: keep DCs, servers, endpoints patched and maintain an asset inventory.
    
- **Network segmentation**: isolate DCs and critical infrastructure from general user networks.
    
- **MFA (multi-factor authentication)**: especially for administrative and remote accesses.
    
- **Limit exposure of legacy protocols** (disable NTLM where possible).
    
- **Use gMSA / managed accounts** where possible for services.
    
- **Apply secure Group Policies** and enforce strong password / account lockout policies.
    
- **Local Administrator Password Solution (LAPS)**: randomizes local admin passwords on endpoints.
    
- **Monitor & logging**: enable auditing on DCs (login failures, sensitive changes), forward logs to SIEM.
    
- **Backup & recovery**: offline backups and tested restore procedures.
    
- **Restrict enumeration**: use ACLs on AD objects where needed; implement protections for high-value objects.
    
- **Harden services that interact with AD** (Exchange, print servers, Azure AD Connect).

---
---

## Active Directory Structure

[Active Directory (AD)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
- A directory service, such as [Active Directory Domain Services (AD DS)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview) gives an organization ways to store directory data and make it available to both standard users and administrators on the same network.
- AD DS stores information such as usernames and passwords and manages the rights needed for authorized users to access this information.

AD user account with no added privileges can be used to enumerate the majority of objects (info) contained within AD

|                                                                                                                                       |                                                                                                                                                                                         |
| ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Domain Computers<br><br>- all machine (workstation or servers) joined to the domain                                                   | Domain Users<br><br>- user accounts                                                                                                                                                     |
| Domain Group Information<br><br>- group and their member                                                                              | Organizational Units (OUs)<br><br>- Containers that organize users/computers and apply policies.<br>- can reveal structure and where high value account and where low policies accounts |
| Default Domain Policy/ Group Policy Objects (GPOs)<br><br>- Policies applied at domain or OU level (password rules, scripts, rights). | Functional Domain Levels<br><br>- AD/Windows feature level (e.g., Server 2016/2019).                                                                                                    |
| Password Policy<br><br>-Rules for password complexity, age, lockout, etc.                                                             | Access Control Lists (ACLs)<br><br>-Permissions on AD objects (who can read/modify/reset/etc.).                                                                                         |
| Domain Trusts<br><br>-Authentication trusts between domains/forests<br>                                                               |                                                                                                                                                                                         |

```
INLANEFREIGHT.LOCAL/
├── ADMIN.INLANEFREIGHT.LOCAL
│   ├── GPOs
│   └── OU
│       └── EMPLOYEES
│           ├── COMPUTERS
│           │   └── FILE01
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── barbara.jones
├── CORP.INLANEFREIGHT.LOCAL
└── DEV.INLANEFREIGHT.LOCAL
```

![](../attachments/Pasted%20image%2020250928222621.png)
The graphic below shows two forests, `INLANEFREIGHT.LOCAL` and `FREIGHTLOGISTICS.LOCAL`. The two-way arrow represents a bidirectional trust between the two forests, meaning that users in `INLANEFREIGHT.LOCAL` can access resources in `FREIGHTLOGISTICS.LOCAL` and vice versa.

---
---

## Active Directory Terminology 

### Objects
- any resource present within an AD env (OU, printers, users, domain ...)

### Attributes
- Every object in Active Directory has an associated set of [attributes](https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all) used to define characteristics of the given object.
- an object contain attributes like DNS name, LDAP name, display name etc

### Schema
- The Active Directory [schema](https://docs.microsoft.com/en-us/windows/win32/ad/schema) is essentially the blueprint of any enterprise environment. It defines what types of objects can exist in the AD database and their associated attributes.
- It lists definitions corresponding to AD objects and holds information about each object
- AD belong to class "user" and computer object "computer"

### Domain
- A domain is a logical group of objects such as computers, users, OUs, groups, etc.
- We can think of each domain as a different city within a state or country.
- it works independently or we can connect with other domain (trust)

### Forest
- A forest is a collection of Active Directory domains. or collection of AD trees
- top most container and contain all the AD objects

### Tree
- A tree is a collection of Active Directory domains that begins at a single root domain.

### container
- Container objects hold other objects and have a defined place in the directory subtree hierarchy.

### leaf
- Leaf objects do not contain other objects and are found at the end of the subtree hierarchy.

### Global Unique Identifier (GUID)
- A [GUID](https://docs.microsoft.com/en-us/windows/win32/adschema/a-objectguid) is a unique 128-bit value assigned when a domain user or group is created.
- its like a MCA unique across the organization 
- every single object created as GUID 
- GUID is stored in the ObjectGUID attribute (used for query)
- The `ObjectGUID` property `never` changes and is associated with the object for as long as that object exists in the domain.

### Security principals
- [Security principals](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals) are anything that the operating system can authenticate,
- We can also have local user accounts and security groups used to control access to resources on only that specific computer. These are not managed by AD but rather by the [Security Accounts Manager (SAM)](https://en.wikipedia.org/wiki/Security_Account_Manager).

### Security Identifier (SID)

- A [security identifier](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals), or SID is used as a unique identifier for a security principal or security group.
- issued by the domain controller and stored in a secure database. A SID can only be used once. Even if the security principal is deleted, it can never be used again in that environment to identify another user or group.
- There are also [well-known SIDs](https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers) that are used to identify generic users and groups. These are the same across all operating systems. An example is the `Everyone` group.

### Distinguished Name (DN)

- A [Distinguished Name (DN)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names) describes the full path to an object in AD (such as `cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local`).

### Relative Distinguished Name (RDN)
- A [Relative Distinguished Name (RDN)](https://docs.microsoft.com/en-us/windows/win32/ad/object-names-and-identities) is a single component of the Distinguished Name that identifies the object as unique from other objects at the current level in the naming hierarchy.
- Just one part of the DN that identifies the object at its level.
- `cn=bjones,dc=dev,dc=inlanefreight,dc=local` is still different from `cn=bjones,dc=inlanefreight,dc=local`.

### sAMAccountName
- The [sAMAccountName](https://docs.microsoft.com/en-us/windows/win32/ad/naming-properties#samaccountname) is the user's logon name.
- old style logon name 

### userPrincipalName
- The [userPrincipalName](https://social.technet.microsoft.com/wiki/contents/articles/52250.active-directory-user-principal-name.aspx) attribute is another way to identify users in AD
- Newer logon name in **email format** → `username@domain`

### FSMO Roles
- To avoid **conflicts** between Domain Controllers (DCs).
- Microsoft separated the various responsibilities that a DC can have into [Flexible Single Master Operation (FSMO)](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/fsmo-roles) roles
- Microsoft split DC responsibilities into **five roles**:
- **Forest-wide (1 each):**
    1. Schema Master (controls schema changes)
    2. Domain Naming Master (adds/removes domains in forest)
- **Domain-wide (1 each per domain):**  
    3. RID Master (issues unique IDs for objects)  
    4. PDC Emulator (time sync, password changes, legacy auth)  
    5. Infrastructure Master (updates references between domains)
- Instead of one boss doing everything, the company split the jobs into **specialized managers** so no single failure breaks the company.

### Global Catalog
- A [global catalog (GC)](https://docs.microsoft.com/en-us/windows/win32/ad/global-catalog) is a domain controller that stores copies of ALL objects in an Active Directory forest.
- The GC allows both users and applications to find information about any objects in ANY domain in the forest.
- its function : authentication (knows which groups a user belongs to) and object search (find a user in the whole forest with just one attribute)

### Read-Only Domain Controller (RODC)
- A [Read-Only Domain Controller (RODC)](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema) has a read-only copy of Active Directory database.
- doesnt store password excepts its own 

### Replication
- [Replication](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts) happens in AD when AD objects are updated and transferred from one Domain Controller to another.
- Managed by the **KCC (Knowledge Consistency Checker)**.
- ensures all DCs are in sync

### Service Principal Name (SPN)
- A [Service Principal Name (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names) uniquely identifies a service instance.
- Unique name that identifies a service instance for **Kerberos authentication**.

### Group policy Object (GPO)
- [Group Policy Objects (GPOs)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-objects) are virtual collections of policy settings. Each GPO has a unique GUID.
- contain local file sys or ad settings 
- applied to both users and computer objects 

### Access Control List (ACL)
- An [Access Control List (ACL)](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) is the ordered collection of Access Control Entries (ACEs) that apply to an object.
- list of permissions for an object 

### Access Control Entries (ACEs)
- Each [Access Control Entry (ACE)](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-entries) in an ACL identifies a trustee (user account, group account, or logon session) and lists the access rights that are allowed, denied, or audited for the given trustee.
- A single rule in the ACL.
- user bob --> read access

### Discretionary Access Control List (DACL)
- DACLs define which security principals are granted or denied access to an object; it contains a list of ACEs.
- When a process tries to access a securable object, the system checks the ACEs in the object's DACL to determine whether or not to grant access.
- If no DACL → everyone gets full access.
- If empty DACL → nobody gets access.

### System Access Control Lists (SACL)
- Allows for administrators to log access attempts that are made to secured objects. ACEs specify the types of access attempts that cause the system to generate a record in the security event log.
- defines what action should be logged/audited
- Log every failed attempt to open a secure file.

### Fully Qualified Domain Name (FQDN)
- An FQDN is the complete name for a specific computer or host
- [host name].[domain name].[tld]
- he FQDN can be used to locate hosts in an Active Directory without knowing the IP address, much like when browsing to a website such as google.com instead of typing in the associated IP address.
-  An example would be the host `DC01` in the domain `INLANEFREIGHT.LOCAL`. The FQDN here would be `DC01.INLANEFREIGHT.LOCAL`.

### Tombstone
- A [tombstone](https://ldapwiki.com/wiki/Wiki.jsp?page=Tombstone) is a container object in AD that holds deleted AD objects.
- When an object is deleted from AD, the object remains for a set period of time known as the `Tombstone Lifetime,` and the `isDeleted` attribute is set to `TRUE`. Once an object exceeds the `Tombstone Lifetime`, it will be entirely removed.
- 60-180 days 

### AD Recycle Bin
- The [AD Recycle Bin](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944) was first introduced in Windows Server 2008 R2 to facilitate the recovery of deleted AD objects.

### SYSVOL
- The [SYSVOL](https://social.technet.microsoft.com/wiki/contents/articles/8548.active-directory-sysvol-and-netlogon.aspx) folder, or share, stores copies of public files in the domain such as system policies, Group Policy settings, logon/logoff scripts, and often contains other types of scripts that are executed to perform various tasks in the AD environment.
- Replicated to all DCs.

### AdminSDHolder
- The [AdminSDHolder](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) object is used to manage ACLs for members of built-in groups in AD marked as privileged
- Protects **privileged groups** (Domain Admins, etc.) from unauthorized ACL changes.
- Its job is to **protect highly privileged accounts** (like Domain Admins) from having their permissions tampered with.

### dsHeuristics
- The [dsHeuristics](https://docs.microsoft.com/en-us/windows/win32/adschema/a-dsheuristics) attribute is a string value set on the Directory Service object used to define multiple forest-wide configuration settings.
- One of these settings is to exclude built-in groups from the [Protected Groups](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) list
- example : Exclude certain groups from AdminSDHolder protection.

### adminCount
- The [adminCount](https://docs.microsoft.com/en-us/windows/win32/adschema/a-admincount) attribute determines whether or not the SDProp process protects a user. If the value is set to `0` or not specified, the user is not protected. If the attribute value is set to `1`, the user is protected.

### Active Directory Users and Computers (ADUC)
- ADUC is a GUI console commonly used for managing users, groups, computers, and contacts in AD. Changes made in ADUC can be done via PowerShell as well.

### ADSI Edit
- ADSI Edit is a GUI tool used to manage objects in AD. It provides access to far more than is available in ADUC and can be used to set or delete any attribute available on an object, add, remove, and move objects as well.

### sIDHistory
- [This](https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unsecure-sid-history-attribute) attribute holds any SIDs that an object was assigned previously. It is usually used in migrations so a user can maintain the same level of access when migrated from one domain to another.

#### NTDS.DIT
- The main **AD database file**.
- Stores: users, groups, attributes, and **password hashes**.
- Location: `C:\Windows\NTDS\NTDS.DIT`
- If the setting [Store password with reversible encryption](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) is enabled, then the NTDS.DIT will also store the cleartext passwords for all users created or who changed their password after this policy was set.

### MSBROWSE
- Old Microsoft networking protocol for browsing network resources
- Could use `nbtstat -A <IP>` to see MSBROWSE master.

---
---

## Active Directory Objects

- any thing in the AD is called as objects

### Users
- Users are considered `leaf objects`, which means that they cannot contain any other objects within them
- User objects have many possible [attributes](http://www.kouti.com/tables/userattributes.htm), such as their display name, last login time, date of last password change, email address, account description, manager, address, and more.
- contain SID and GUID
-  ALL possible attributes as detailed [here](https://www.easy365manager.com/how-to-get-all-active-directory-user-object-attributes/).

### Contacts
- its usually represents an external person not in the domain 
- we will have limited info on them
- so they dont have the any GUID

### Printers
A printer object points to a printer accessible within the AD network. Like a contact, a printer is a `leaf object` and not a security principal, so it only has a GUID

### computers
- any workstation or server in the AD
- leaf objects
- have SID and GUID

### Shared Folders
- A **shared folder object** in Active Directory is basically a **shortcut/pointer** to a real shared folder that exists on a computer/server in the network.
- we can set up permission so that who can access this 

### Groups
- A **group** is a **container object** → it can hold **users, computers, and even other groups**.
- has SID and GUID
- A group can be a **member of another group** → this is called **nesting**.

### Organizational Units (OUs)
- An **OU (Organizational Unit)** is a **container object** in AD.
- It’s used to **organize objects** (users, computers, groups, etc.) into logical units.
- **Organization** → You can group objects by department, function, or location.
- **Delegation of Administration** →
	- You don’t always want to give **Domain Admin rights** to everyone.
	- With OUs, you can **assign specific rights** over specific OUs.  
    Example:
    - Help Desk staff → can reset passwords only for users in the **Help Desk OU**, not across the whole company.
- **Group Policy Management** →OUs are the main target for **Group Policy Objects (GPOs)**.

### Domains
- A domain is the structure of an AD network. Domains contain objects such as users and computers, which are organized into container objects: groups and OUs.

### Domain Controllers
Domain Controllers are essentially the brains of an AD network. They handle authentication requests, verify users on the network, and control who can access the various resources in the domain.

### Sites
A site in AD is a set of computers across one or more subnets connected using high-speed links. They are used to make replication across domain controllers run efficiently.

### Built-in
In AD, built-in is a container that holds [default groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups) in an AD domain. They are predefined when an AD domain is created.

### Foreign Security Principals

- A foreign security principal (FSP) is an object created in AD to represent a security principal that belongs to a trusted external forest.
-  They are created when an object such as a user, group, or computer from an external (outside of the current) forest is added to a group in the current domain.
- FSPs are created in a specific container named ForeignSecurityPrincipals with a distinguished name like `cn=ForeignSecurityPrincipals,dc=inlanefreight,dc=local`.

---
---

##  Active Directory Functionality

|**Roles**|**Description**|
|---|---|
|`Schema Master`|This role manages the read/write copy of the AD schema, which defines all attributes that can apply to an object in AD.|
|`Domain Naming Master`|Manages domain names and ensures that two domains of the same name are not created in the same forest.|
|`Relative ID (RID) Master`|The RID Master assigns blocks of RIDs to other DCs within the domain that can be used for new objects. The RID Master helps ensure that multiple objects are not assigned the same SID. Domain object SIDs are the domain SID combined with the RID number assigned to the object to make the unique SID.|
|`PDC Emulator`|The host with this role would be the authoritative DC in the domain and respond to authentication requests, password changes, and manage Group Policy Objects (GPOs). The PDC Emulator also maintains time within the domain.|
|`Infrastructure Master`|This role translates GUIDs, SIDs, and DNs between domains. This role is used in organizations with multiple domains in a single forest. The Infrastructure Master helps them to communicate. If this role is not functioning properly, Access Control Lists (ACLs) will show SIDs instead of fully resolved names.|

 [This](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754918\(v=ws.10\)?redirectedfrom=MSDN) and [this](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels) article describe both the domain and forest functional levels from Windows 2000 native to Windows Server 2012 R2.

| Domain Functional Level | Features Available                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Supported Domain Controller Operating Systems                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| Windows 2000 native     | Universal groups for distribution and security groups, group nesting, group conversion (between security and distribution and security groups), SID history.                                                                                                                                                                                                                                                                                                                               | Windows Server 2008 R2, Windows Server 2008, Windows Server 2003, Windows 2000                                |
| Windows Server 2003     | Netdom.exe domain management tool, lastLogonTimestamp attribute introduced, well-known users and computers containers, constrained delegation, selective authentication.                                                                                                                                                                                                                                                                                                                   | Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2, Windows Server 2008, Windows Server 2003 |
| Windows Server 2008     | Distributed File System (DFS) replication support, Advanced Encryption Standard (AES 128 and AES 256) support for the Kerberos protocol, Fine-grained password policies                                                                                                                                                                                                                                                                                                                    | Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2, Windows Server 2008                      |
| Windows Server 2008 R2  | Authentication mechanism assurance, Managed Service Accounts                                                                                                                                                                                                                                                                                                                                                                                                                               | Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2                                           |
| Windows Server 2012     | KDC support for claims, compound authentication, and Kerberos armoring                                                                                                                                                                                                                                                                                                                                                                                                                     | Windows Server 2012 R2, Windows Server 2012                                                                   |
| Windows Server 2012 R2  | Extra protections for members of the Protected Users group, Authentication Policies, Authentication Policy Silos                                                                                                                                                                                                                                                                                                                                                                           | Windows Server 2012 R2                                                                                        |
| Windows Server 2016     | [Smart card required for interactive logon](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-require-smart-card) new [Kerberos](https://docs.microsoft.com/en-us/windows-server/security/kerberos/whats-new-in-kerberos-authentication) features and new [credential protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/whats-new-in-credential-protection) features |                                                                                                               |
he target domain has to use [DFS-R](https://docs.microsoft.com/en-us/windows-server/storage/dfs-replication/dfsr-overview) for SYSVOL replication.

Forest functional levels have introduced a few key capabilities over the years:

|**Version**|**Capabilities**|
|---|---|
|`Windows Server 2003`|saw the introduction of the forest trust, domain renaming, read-only domain controllers (RODC), and more.|
|`Windows Server 2008`|All new domains added to the forest default to the Server 2008 domain functional level. No additional new features.|
|`Windows Server 2008 R2`|Active Directory Recycle Bin provides the ability to restore deleted objects when AD DS is running.|
|`Windows Server 2012`|All new domains added to the forest default to the Server 2012 domain functional level. No additional new features.|
|`Windows Server 2012 R2`|All new domains added to the forest default to the Server 2012 R2 domain functional level. No additional new features.|
|`Windows Server 2016`|[Privileged access management (PAM) using Microsoft Identity Manager (MIM).](https://docs.microsoft.com/en-us/windows-server/identity/whats-new-active-directory-domain-services#privileged-access-management)|
### Trusts
A trust is used to establish `forest-forest` or `domain-domain` authentication, allowing users to access resources in (or administer) another domain outside of the domain their account resides in. A trust creates a link between the authentication systems of two domains.

|**Trust Type**|**Description**|
|---|---|
|`Parent-child`|Domains within the same forest. The child domain has a two-way transitive trust with the parent domain.|
|`Cross-link`|a trust between child domains to speed up authentication.|
|`External`|A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering.|
|`Tree-root`|a two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.|
|`Forest`|a transitive trust between two forest root domains.|

![](../attachments/Pasted%20image%2020251001104742.png)

Trusts can be transitive or non-transitive.

- A transitive trust means that trust is extended to objects that the child domain trusts.
    
- In a non-transitive trust, only the child domain itself is trusted.

Trusts can be set up to be one-way or two-way (bidirectional).

- In bidirectional trusts, users from both trusting domains can access resources.
- In a one-way trust, only users in a trusted domain can access resources in a trusting domain, not vice-versa. The direction of trust is opposite to the direction of access.

---
---

## Kerberos, DNS, LDAP, MSRPC

While Windows operating systems use a variety of protocols to communicate, Active Directory specifically requires [Lightweight Directory Access Protocol (LDAP)](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol), Microsoft's version of [Kerberos](https://en.wikipedia.org/wiki/Kerberos_\(protocol\)), [DNS](https://en.wikipedia.org/wiki/Domain_Name_System) for authentication and communication, and [MSRPC](https://ldapwiki.com/wiki/MSRPC) which is the Microsoft implementation of [Remote Procedure Call (RPC)](https://en.wikipedia.org/wiki/Remote_procedure_call), an interprocess communication technique used for client-server model-based applications.

### Kerberos

- **Kerberos** is the **default authentication protocol** in Windows domains (since Windows 2000).
- It’s **ticket-based** → Instead of sending your password over the network, Kerberos uses special tokens called _tickets_ to prove your identity.
- It uses **mutual authentication** → The **user proves to the server**, and the **server proves to the user**.
- It is **stateless** → The Domain Controller (KDC) does not keep track of old sessions; it just validates tickets.

#### key components


| components                                                                                        | description                                                                                           |
| :------------------------------------------------------------------------------------------------ | :---------------------------------------------------------------------------------------------------- |
| KDC (key distribution center)<br>- AS (authentication service)<br>- TGS (ticket granting service) | Lives on the Domain Controller<br>issues TGT (ticket granting ticket)<br>issues service tickets (TGS) |
| TGT (ticket granting ticket)                                                                      | proof that you are who you say you are . you use it to get service tickets                            |
| TGS (ticket granting service ticket)                                                              | Proof that you can access a specific service (e.g., file share, SQL server).                          |
| krbtgt acount                                                                                     | a special hidden AD account that sign/encrypts tickets                                                |

![](../attachments/Pasted%20image%2020251001130205.png)

- **AS-REQ** (Authentication Request)  
    User encrypts timestamp with their password hash and sends to KDC.
    
- **AS-REP** (Response)  
    KDC verifies and gives back a **TGT** (signed with `krbtgt` account).
    
- **TGS-REQ**  
    User presents TGT to KDC asking for a service ticket (e.g., for `CIFS/file01`).
    
- **TGS-REP**  
    KDC issues a **TGS**, encrypted with the target service’s password hash.
    
- **AP-REQ**  
    User presents the TGS to the service. If it matches, service grants access.

uses TCP/UDP 88 port

### DNS

- DNS is like the **phonebook of the internet and networks**.
- it translates hostnames to ip addresses so computers can talk to each other
- **AD DS (Active Directory Domain Services)** is built on top of DNS.
- Clients (workstations, laptops, servers) rely on DNS to **find Domain Controllers**.
- Domain Controllers themselves use DNS to **find and talk to each other**.

#### key AD DNS components


| components                    | description                                                                                                                                           |
| :---------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------- |
| SRV records (service records) | special DNS entries that tell client where service are located<br>Example: `_ldap._tcp.dc._msdcs.ad.local` → lists all the DCs offering LDAP service. |
| Dynamic DNS (DDNS)            | computers automatically update their DNS records when their IP changes<br>saves admin form manually records<br>prevents mismatches                    |
| Namespace                     | AD uses its own DNS namespace (e.g., `company.local` or `corp.example.com`) for internal communication.                                               |


- **UDP 53** → Default, faster, used for most DNS queries.
- **TCP 53** → Used if:
    - Query/response is too large (>512 bytes), or
    - Zone transfers between DNS servers are happening.

```shell
#foward DNS lookup
nslookup INLANEFREIGHT.LOCAL

#reverse DNS lookup
nslookup 172.16.6.5

#finding the iP address of a host
nslookup ACADEMY-EA-DC01
```

For deeper dives into DNS, check out the [DNS Enumeration Using Python](https://academy.hackthebox.com/course/preview/dns-enumeration-using-python) module and the DNS section of the [Information Gathering - Web Edition](https://academy.hackthebox.com/course/preview/information-gathering---web-edition) module.

### LDAP
- **LDAP (Lightweight Directory Access Protocol)** = A **protocol** used to query and interact with directory services.  [Lightweight Directory Access Protocol (LDAP)](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)
- Think of it as the **language** that applications and systems use to talk to a directory (like AD).
- In AD’s case → **Active Directory = the service**, **LDAP = the protocol**.
- like apache <--> HTTP and AD <---> LDAP
- AD stores lots of data: **users, groups, computers, OUs, policies, permissions**.
- LDAP provides a way for apps, services, or devices to **search, query, and authenticate against this data**.
- Example: When you log in to a corporate app, it may ask AD (via LDAP): _“Does this username/password exist?”
- **LDAP (unencrypted)** → Port **389 (TCP/UDP)**
- **LDAP over SSL (LDAPS)** → Port **636 (TCP)**

#### LDAP authentication (BIND)

When you "bind," you’re telling the LDAP server: _“Here are my credentials—please authenticate me.”_
There are two main types:
1. **Simple Authentication**
    - Username + Password → sent in a BIND request.
    - Variants: anonymous, unauthenticated, or plain user/password.
    - **Problem**: Without encryption, password is in cleartext.
2. **SASL Authentication (Simple Authentication and Security Layer)** [The Simple Authentication and Security Layer (SASL)](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer)
    - Uses external auth mechanisms (like **Kerberos**).
    - LDAP just forwards the request.
    - Stronger security since credentials don’t travel in plain text.

![](../attachments/Pasted%20image%2020251001133157.png)

While uncommon, you may come across organization while performing an assessment that do not have AD but are using LDAP, meaning that they most likely use another type of LDAP server such as [OpenLDAP](https://en.wikipedia.org/wiki/OpenLDAP).
The latest LDAP specification is [Version 3](https://tools.ietf.org/html/rfc4511), published as RFC 4511.

### MSRPC

- **MSRPC** = Microsoft’s implementation of RPC (Remote Procedure Call), a mechanism to let programs on one machine invoke functions on another machine as if local.\
- RPC services expose _interfaces_ (APIs) that clients call over the network — many AD operations use RPC under the hood.

#### Important transport details
- **RPC endpoint mapper:** TCP **135** — clients contact this to find which dynamic port an RPC service is listening on.
- **Dynamic RPC ports:** Modern Windows uses a dynamic high port range (default **49152–65535** on modern Windows) for RPC endpoints; older systems used **1024–5000**.
- RPC can also be accessed over **named pipes** (e.g., `\\<host>\pipe\samr`) and via DCOM.
- When hunting or hardening, remember both TCP 135 and the dynamic high port range matter.

The four key AD RPC interfaces (what they do, why they matter)

#### 1. `lsarpc` (LSA RPC)

- Talks to the **Local Security Authority** (LSA). LSA manages local security policy, account rights, auditing, and interactive authentication.
    
- Uses: reading/changing security policy, audit settings, and other LSA-managed objects.
    
- Risk: LSA is privileged — abuse can expose sensitive security configuration/credentials.

#### 2. `netlogon`

- The **Netlogon** service authenticates users/computers with domain controllers and supports secure channel management between machines and DCs.
    
- Uses: authenticating machine accounts, establishing secure channels, replicating secrets between DCs and members.
    
- Risk: Attacks that tamper with Netlogon or its secrets can allow credential or secure-channel abuse.
#### 3. `samr` (Remote SAM)

- `samr` manages the **Security Account Manager (SAM)** and domain account database: users, groups, SIDs, RIDs, etc.
    
- Uses: administrative account creation/modification and also read-only enumeration of users/groups.
    
- Why attackers like it: wide reconnaissance — an authenticated user can query lots of AD objects (users, groups, privileges) and map out targets. Tools like **BloodHound** and `rpcclient`/impacket use `samr` for enumeration.
    
- Mitigation note: By default many samr queries are allowed to _authenticated users_; you can harden environments to restrict who can perform remote SAM queries (best practice: limit to admins).
#### 4. `drsuapi` (Directory Replication / DRS Remote API)

- Implements AD **Directory Replication** operations used by DCs to replicate changes (the DRS Remote Protocol).
    
- Uses: replication between DCs, transfer of directory data (including attributes like password hashes in the database).
    
- Why attackers like it: it enables replication-style access to directory data. Tools/techniques (e.g., **DCSync**, some `impacket` tools, or abusing replication privileges) let an attacker request account credential material from a DC without needing to compromise the DC fully. This can yield NTLM hashes / Kerberos keys for many accounts — effectively domain-wide secrets.

---
---

## NTLM Authentication

- Aside from Kerberos and LDAP, AD also supports **LM, NTLM, NTLMv1, and NTLMv2**.
- **LM and NTLM** → refer to **hash types**.
- **NTLMv1 and NTLMv2** → are **authentication protocols** that use those hashes.
- While still in use, these are weaker than **Kerberos**, which is usually preferred.

| Hash/Protocol | Cryptographic Technique             | Mutual Authentication | Message Type                | Trusted Third Party     |
| ------------- | ----------------------------------- | --------------------- | --------------------------- | ----------------------- |
| **NTLM**      | Symmetric key cryptography          | No                    | Random number               | Domain Controller       |
| **NTLMv1**    | Symmetric key cryptography          | No                    | MD4 hash, random number     | Domain Controller       |
| **NTLMv2**    | Symmetric key cryptography          | No                    | MD4 hash, random number     | Domain Controller       |
| **Kerberos**  | Symmetric + asymmetric cryptography | Yes                   | Encrypted ticket (DES, MD5) | Domain Controller / KDC |

- **Symmetric** → **same key** for encryption and decryption.
    
- **Asymmetric** → **different keys** (public + private) for encryption and decryption.

#### LM (LAN Manager)
- Oldest Windows password hash (since 1987).
    
- Stored in **SAM** or **NTDS.dit** if used. Disabled by default since Vista/Server 2008 but still found on old systems.
    
- Passwords max **14 characters**, converted to **uppercase**, split into **two 7-char** chunks, each turned into a DES key and encrypted with the fixed string `KGS!@#$%`, then concatenated → **LM hash**.
    
- Weak because attackers only need to brute-force 7 chars twice; second half is constant for ≤7 char passwords.
    
- Example LM-like value: `299bd128c1101fd6`.
    
- Older Windows stored both LM and NT hashes by default.

#### NTHash (NTLM hash)

- Modern Windows use the **NT hash** (MD4 of the UTF-16-LE password): `MD4(UTF-16-LE(password))`.
    
- Stored in SAM or NTDS.dit. Stronger charset support (Unicode) but still crackable offline with GPUs for short passwords.
    
- NT hash example: `b4b9b02e6f09a9bd760f388b67351e2b`.
    
- Full NTLM account entry example (fields):  
    `Rachel:500:<LM_hash>:<NT_hash>:::`
    
    - `Rachel` = username
        
    - `500` = RID (admin)
        
    - `<LM_hash>` = LM (might be disabled)
        
    - `<NT_hash>` = NT hash (can be cracked or used in pass-the-hash)

![](../attachments/Pasted%20image%2020251001151456.png)

```shell-session
crackmapexec smb 10.129.41.19 -u rachel -H e46b9e548fa0d122de7f59fb6d48eaa2
```

**Note:** Neither LANMAN nor NTLM uses a salt.
#### NTLM (protocol overview)

- Challenge/response protocol using the NT hash.
    
- Three messages: `NEGOTIATE_MESSAGE` → `CHALLENGE_MESSAGE` → `AUTHENTICATE_MESSAGE`.
    
- Supports NT hash (and LM if present) for authentication.
    
- Vulnerable to **pass-the-hash**: attacker can use the NT hash directly to authenticate without knowing the plaintext password.

#### NTLMv1 (Net-NTLMv1)

- Uses NT and LM hashes in a challenge/response.
    
- Server sends 8-byte challenge; client returns 24-byte response built from DES of keys derived from hashes.
    
- Not usable for pass-the-hash attacks.
    
- Example v1 structure: `response = DES(K1,C) | DES(K2,C) | DES(K3,C)`
    
- Example NTLMv1 string shown in your content.
    

---

#### NTLMv2 (Net-NTLMv2)

- Introduced as stronger replacement; default since Server 2000.
    
- Sends two responses to the server challenge: includes HMAC-MD5 over NT-Hash, server challenge, client challenge, time, domain name.
    
- Response structure (simplified from your content): `response = LMv2 | CC | NTv2 | CC*` where `LMv2` and `NTv2` are HMAC-MD5 outputs.
    
- Example NTLMv2 string shown in your content.
    

---

#### Domain Cached Credentials (MSCache2 / DCC)

- Allows login when DC is unreachable.
    
- Host caches up to **last 10 hashes** in `HKLM\SECURITY\Cache`.
    
- These cached hashes **cannot** be used for pass-the-hash and are **slow to crack**.
    
- Format example from your content: `$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90f`.
    
- Obtaining them requires local admin on the host.

---
---

## User and Machine Accounts

#### User Accounts

- Created locally (on standalone systems) or in AD.
- Purpose: let a person or program log in and access resources.
- When user logs in → password verified → **access token** created (contains user ID + group memberships).
- Token is presented whenever user interacts with processes/resources.
- Users can belong to **groups** → groups inherit rights collectively (easier for admins to manage).
User accounts = the backbone of AD access but also a **prime target for attackers** due to misconfigurations and human errors.

#### Local accounts

**Stored locally** on a specific server/workstation.
- Rights granted to a local account apply **only to that host**.
- Local accounts are security principals but cannot manage domain resources.

**Common default local accounts**
- **Administrator**
    - SID: `S-1-5-domain-500` (first account created on a new install).
    - Full control over almost every resource on the system.
    - Cannot be deleted or locked, but **can** be disabled or renamed.
    - Windows 10 / Server 2016 disable the built-in Administrator by default and create another local admin account during setup.

- **Guest**
    - Disabled by default.
    - Intended for temporary logins with limited access.
    - Default password is blank — recommended to keep disabled for security.

- **SYSTEM (NT AUTHORITY\SYSTEM)**
    - The OS’s built-in service account used to run many internal functions and services.
    - Has permissions over almost everything on the host (highest local permission).
    - No profile, doesn’t appear in User Manager, and cannot be added to groups.

- **Network Service**
    - Predefined local account used by the Service Control Manager (SCM) to run services.
    - When a service runs as this account, it **presents credentials to remote services**.

- **Local Service**
    - Another predefined SCM account with **minimal privileges**.
    - Presents **anonymous credentials** to the network.

It is worth studying Microsoft's documentation on [local default accounts](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts) in-depth to gain a better understanding

#### Domain Users (concise)
- **Domain users** get rights from the **domain** to access resources (file servers, printers, intranet hosts, etc.) based on the permissions on their account or groups they belong to.
- **Domain accounts** can log in to **any host in the domain** (unlike local accounts, which are host-specific).
- A special account to remember: **KRBTGT**
    - A built-in **service account** for the Key Distribution service (KDC) that issues Kerberos tickets.
    - **High-value target** for attackers — control of KRBTGT can enable wide access, privilege escalation, and persistence (e.g., Golden Ticket attacks).

#### User Naming Attributes in AD

- **UserPrincipalName (UPN):** Primary logon name, usually in email format (`user@domain.com`).
- **ObjectGUID:** Unique, never-changing identifier for the user object.
- **SAMAccountName:** Legacy logon name (for older Windows systems).
- **objectSID:** Security Identifier (SID) — defines the user and their group memberships.
- **sIDHistory:** Stores old SIDs after domain migrations, so the user keeps access to previous resources.

#### Common User Attributes

```powershell
PS C:\htb Get-ADUser -Identity htb-student

DistinguishedName : CN=htb student,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
Enabled           : True
GivenName         : htb
Name              : htb student
ObjectClass       : user
ObjectGUID        : aa799587-c641-4c23-a2f7-75850b4dd7e3
SamAccountName    : htb-student
SID               : S-1-5-21-3842939050-3880317879-2865463114-1111
Surname           : student
UserPrincipalName : htb-student@INLANEFREIGHT.LOCAL
```

For a deeper look at user object attributes  [page](https://docs.microsoft.com/en-us/windows/win32/ad/user-object-attributes)

#### Domain-joined
- Joined to an Active Directory domain.
- Centrally managed by Domain Controllers (DCs) via **Group Policy**.
- Easier information sharing across the enterprise.
- Users can log in and access resources from **any host** joined to the domain.
- Typical for enterprise environments.
#### Non-domain-joined (Workgroup)
- Not managed by domain policy.
- Best for home or small-business LANs.
- Users manage changes locally; user accounts exist **only on that host**.
- Profiles and accounts do **not** migrate to other hosts in the workgroup.
#### Important note about MACHINE / SYSTEM access
- A **machine account** (SYSTEM-level) on a domain-joined host has many of the same rights as a standard domain user.
- Gaining **SYSTEM** on a domain-joined host (via exploit or privilege escalation) provides powerful read access across the domain and is an excellent starting point for domain enumeration and further AD attacks.

---
---

## Active Directory Groups

- Used to **group users together** and assign rights/access in bulk.
- Important target for attackers since group memberships may grant **hidden or excessive privileges**.
- Organizations create both **built-in** and **custom** groups → can quickly become hard to manage.
- Risk: too many groups or poorly managed memberships can cause **unintended access**.
- Best practice: periodically **audit groups, privileges, and memberships**.

- **Groups** → primarily used to **assign permissions to resources**.
- **OUs** → mainly for **management** (organizing users, groups, computers; applying Group Policy).
- OUs can also delegate **admin tasks** (e.g., reset passwords, unlock accounts) without giving broad rights.

#### Why Groups?
- Easier to manage permissions/resources (like printers, file shares).
- Instead of adding 50 users one by one → put them in **one group**.a
- Adding/removing users from the group updates their permissions automatically.

#### Group Characteristics
1. **Type** → defines the **purpose**.
2. **Scope** → defines **how/where the group can be used** in the domain/forest.

#### Group Types
- **Security Groups**
    - Used to assign **permissions & rights** to many users at once.
    - All members inherit permissions.
    - Main use: simplify access control.
- **Distribution Groups**
    - Used for **email distribution** (like mailing lists).
    - Example: Microsoft Exchange → send one email to the group, all members get it.
    - ⚠️ Cannot be used for permissions to resources.

#### Group Scopes in AD

1. **Domain Local Group**
	- Works **only in the domain it was created in**.
	- Can contain **users from other domains**.
	- Can be nested into other **local groups**, but **NOT global groups**.
	- Use: assign permissions to resources in the same domain.

2. **Global Group**
	- Can be used to grant access in **other domains**.
	- Can only contain **accounts from its own domain**.
	- Can be nested into **global groups and local groups**.
	- Use: collect users from one domain, then assign permissions elsewhere.

3. **Universal Group**
	- Works **across the whole forest**.
	- Can contain users from **any domain**.
	- Stored in the **Global Catalog (GC)**.
	- Adding/removing members = **forest-wide replication** ⚠️ (so better to add global groups instead of individual users).
	- Use: enterprise-wide permissions across domains.

 **Conversion Rules (Caveats)**

- Global → Universal ✅ (only if not inside another Global group).
    
- Domain Local → Universal ✅ (only if no Domain Local groups inside it).
    
- Universal → Domain Local ✅ (no restriction).
    
- Universal → Global ✅ (only if no Universal groups inside it).
---
- **Domain Local** = permissions **inside domain**.
    
- **Global** = users **from one domain**, permissions anywhere.
    
- **Universal** = permissions/resources **across forest**.

#### Built-in vs Custom Groups

 **Built-in Groups**

- Created automatically when a domain is set up.
    
- Mostly **Domain Local scope**.
    
- **No group nesting** → only user accounts can be added.
    
- Example:
    
    - **Domain Admins** → Global group (only accounts from its own domain).
        
    - If cross-domain access is needed, you add the account to the **Administrators** (Domain Local) group.

**Custom Groups**

- Created by organizations as needed (security or distribution).
    
- Used to manage **permissions, rights, or email lists**.
    
- Extra groups may also appear when new services (e.g., **Microsoft Exchange**) are installed.
    
- ⚠️ Some of these new groups can be **highly privileged** → if unmanaged, attackers can abuse them.

#### Nested Group Membership

- **What it means:**  
    Groups can be members of other groups.  
    → A user may gain privileges indirectly through group nesting.
    
- **Example:**
    
    - User **DCorner** is not directly in _Helpdesk Level 1_.
        
    - But **Help Desk** is a member of _Helpdesk Level 1_.
        
    - Result: DCorner inherits _Helpdesk Level 1_ rights (like adding members to _Tier 1 Admins_).
        
    - This could escalate into **local admin** or higher domain privileges.
        
- **Why it matters:**
    
    - Privileges may be hidden or **not obvious**.
        
    - Attackers love this → can chain nested memberships for privilege escalation.
        
    - **BloodHound** is the go-to tool for visualizing and discovering hidden access paths.

Like users, groups have many [attributes](http://www.selfadsi.org/group-attributes.htm). Some of the most [important group attributes](https://docs.microsoft.com/en-us/windows/win32/ad/group-objects) include:
- **cn (Common Name):** Display name of the group.
- **member:** Lists all direct members (users, groups, contacts).
- **groupType:** Shows **type + scope** (security/distribution, local/global/universal).
- **memberOf:** Lists **parent groups** (used to track nesting).
- **objectSid:** Unique security identifier (used to enforce permissions).

---
---

## Active Directory Rights and Privileges

- **Rights** → Control _what you can access_ (e.g., a file, folder, or resource).
- **Privileges** → Control _what actions you can perform_ (e.g., reset a password, shut down a system).

In Active Directory:
- Rights are usually assigned to users or groups for specific objects.
- Privileges can be assigned directly or granted through group membership.

### built-in AD groups

AD contains many [default or built-in security groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups),

| **Group Name**                         | **Description / Privileges**                                                                                                                                                                                     |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Account Operators**                  | Can create/modify most accounts (users, local/global groups), log in locally to DCs; cannot manage Administrator account or members of high-privilege groups.                                                    |
| **Administrators**                     | Full and unrestricted access to a computer or the entire domain (on DCs).                                                                                                                                        |
| **Backup Operators**                   | Can back up/restore all files, log on locally, shut down computers, and access DCs; can create shadow copies of SAM/NTDS.                                                                                        |
| **DnsAdmins**                          | Access to network DNS information; created if DNS role exists/was installed on a DC.                                                                                                                             |
| **Domain Admins**                      | Full domain administration; members are local admins on all domain-joined machines.                                                                                                                              |
| **Domain Computers**                   | Contains all non-DC computers in the domain.                                                                                                                                                                     |
| **Domain Controllers**                 | Contains all DCs in the domain; new DCs auto-added.                                                                                                                                                              |
| **Domain Guests**                      | Includes domain's Guest account; members get domain profile when logging in.                                                                                                                                     |
| **Domain Users**                       | Contains all user accounts; new accounts auto-added.                                                                                                                                                             |
| **Enterprise Admins**                  | Full configuration access across the AD forest; can make forest-wide changes (e.g., add child domains, create trusts).                                                                                           |
| **Event Log Readers**                  | Can read event logs on local computers; created on DC promotion.                                                                                                                                                 |
| **Group Policy Creator Owners**        | Can create, edit, or delete Group Policy Objects (GPOs).                                                                                                                                                         |
| **Hyper-V Administrators**             | Full access to Hyper-V; virtualization admins may be treated as Domain Admins if virtual DCs exist.                                                                                                              |
| **IIS_IUSRS**                          | Used by Internet Information Services (IIS) starting with IIS 7.0.                                                                                                                                               |
| **Pre–Windows 2000 Compatible Access** | For backward compatibility with Windows NT 4.0; may allow network users to read AD info without valid credentials.                                                                                               |
| **Print Operators**                    | Manage/create/share/delete printers on DCs; can log on to DCs locally; may escalate privileges via printer drivers.                                                                                              |
| **Protected Users**                    | Extra protections against credential theft and Kerberos attacks.  [group](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#protected-users) |
| **Read-only Domain Controllers**       | Contains all Read-only DCs in the domain.                                                                                                                                                                        |
| **Remote Desktop Users**               | Grants RDP access to hosts; cannot be renamed, deleted, or moved.                                                                                                                                                |
| **Remote Management Users**            | Grants remote access via WinRM.  [Windows Remote Management (WinRM)](https://docs.microsoft.com/en-us/windows/win32/winrm/portal)                                                                                |
| **Schema Admins**                      | Can modify the AD schema; exists only in root domain; default member is the forest root Administrator.                                                                                                           |
| **Server Operators**                   | Only on DCs; can modify services, access SMB shares, and back up files; by default has no members.                                                                                                               |

This table focuses on the key privileges and potential security implications of each built-in group.

#### Server Operators Group Details

```powershell
PS C:\htb>  Get-ADGroup -Identity "Server Operators" -Properties *
```

#### Domain Admins Group Membership

```powershell
PS C:\htb>  Get-ADGroup -Identity "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members
```


#### User Rights Assignments
[User Rights Assignment](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment)
we could potentially leverage a tool such as [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) to assign targeted rights to a user.

| **Privilege**                     | **Description**                                                                    | **Potential Impact / Abuse**                                                                                                                    |
| --------------------------------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **SeRemoteInteractiveLogonRight** | Allows a user to log on to a host via Remote Desktop Protocol (RDP).               | Can be abused to gain interactive access to a host for data theft, lateral movement, or privilege escalation.                                   |
| **SeBackupPrivilege**             | Grants the ability to back up system files, regardless of file permissions.        | Can be used to copy sensitive system files (e.g., SAM, SYSTEM hives, NTDS.dit) to obtain credentials or domain data.                            |
| **SeDebugPrivilege**              | Allows debugging and modifying the memory of processes.                            | Attackers can use tools like [Mimikatz](https://github.com/ParrotSec/mimikatz) to extract credentials from LSASS or other privileged processes. |
| **SeImpersonatePrivilege**        | Lets a process impersonate a token of another account (e.g., NT AUTHORITY\SYSTEM). | Enables privilege escalation using tools like JuicyPotato, RogueWinRM, or PrintSpoofer.                                                         |
| **SeLoadDriverPrivilege**         | Allows a user to load and unload device drivers.                                   | Can be exploited to install malicious drivers for privilege escalation or persistent control.                                                   |
| **SeTakeOwnershipPrivilege**      | Allows a process to take ownership of objects.                                     | Can be abused to gain access to restricted files or file shares, potentially leading to data exfiltration or privilege escalation.              |
- **User Rights vs. Group Membership**: These rights can be assigned directly to accounts or inherited through group membership and Group Policy Objects (GPOs).
- **Abuse Potential**: Each right can have powerful consequences in a security context. Even one misconfigured privilege can allow attackers to escalate from a standard user to a high-level account like Domain Admin.
- **Audit & Restrict**: Security teams must regularly audit accounts, GPOs, and group memberships to ensure unnecessary privileges aren’t assigned.
There are many techniques available to abuse user rights detailed [here](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e) and [here](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.html).


#### Viewing a User’s Privileges in Windows Active Directory

 **Command Used**

```
whoami /priv
```

- **Purpose**: Displays all **user rights (privileges)** assigned to the currently logged-in user.
    
- **Output**: Lists privilege names, their descriptions, and whether they are currently **Enabled** or **Disabled**.
    
- **Note**: Some privileges only appear or are enabled when running an **elevated session** (Administrator-level) due to **User Account Control (UAC)**.
    

---

 **User Account Control (UAC)**

- Security feature introduced in Windows Vista.
    
- Prevents applications (even if running under an administrator account) from automatically running with full privileges unless explicitly elevated.
    
- Requires explicit elevation for certain administrative tasks.
    
- This means privileges differ **based on whether the session is elevated or not**.

 **Examples of Privileges by User Role**
 **1. Standard Domain User Privileges**

Command:

```
whoami /priv
```

Example Output:

```
Privilege Name                Description                     State
============================= =============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

**Key points**:

- Limited privileges.
    
- No dangerous rights (like debugging, backup, or shutdown privileges) are available.

 **2. Domain Admin Privileges**

**a) Non-Elevated Console** (regular admin session without elevation)

```
whoami /priv
```

Example Output:

```
Privilege Name                Description                       State
============================= ================================== ========
SeShutdownPrivilege           Shut down the system              Disabled
SeChangeNotifyPrivilege       Bypass traverse checking          Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set    Disabled
SeTimeZonePrivilege           Change the time zone              Disabled
```

**Key points**:

- Many admin privileges appear **disabled** without elevation.
    
- UAC limits privilege availability even for Domain Admins.


**b) Elevated Console** (Administrator-level session)

```
whoami /priv
```

Example Output:

```
Privilege Name                            Description                                                      State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                               Disabled
SeMachineAccountPrivilege                 Add workstations to domain                                       Disabled
SeSecurityPrivilege                       Manage auditing and security log                                 Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or objects                               Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                   Disabled
SeSystemProfilePrivilege                  Profile system performance                                       Disabled
SeSystemtimePrivilege                     Change the system time                                           Disabled
SeProfileSingleProcessPrivilege           Profile single process                                            Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                     Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                Disabled
SeBackupPrivilege                         Back up files and directories                                    Disabled
SeRestorePrivilege                        Restore files and directories                                    Disabled
SeShutdownPrivilege                       Shut down the system                                             Disabled
SeDebugPrivilege                          Debug programs                                                   Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                               Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                         Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                              Disabled
SeUndockPrivilege                         Remove computer from docking station                             Disabled
SeEnableDelegationPrivilege               Enable accounts to be trusted for delegation                     Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                 Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                        Enabled
SeCreateGlobalPrivilege                   Create global objects                                            Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                   Disabled
SeTimeZonePrivilege                       Change the time zone                                             Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                            Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain impersonation token in same session                      Disabled
```

**Key points**:

- Elevated sessions show **many powerful privileges** that can be abused for attacks (e.g., SeBackupPrivilege, SeDebugPrivilege, SeTakeOwnershipPrivilege).
    
- Privileges differ based on account role and group membership.

**3. Backup Operator Privileges**

```
whoami /priv
```

Example Output:

```
Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

**Key points**:

- Backup Operators have specific privileges such as SeBackupPrivilege (hidden by UAC unless elevated).
    
- Even non-admin groups can have important privileges that must be monitored.

**Security Considerations**

- Membership in built-in security groups grants rights that may be abused for privilege escalation.
    
- **Best practice**: Keep membership in sensitive groups minimal and strictly controlled.
    
- Audit group membership and privileges regularly to prevent accidental privilege escalation.
    
- **Strong account hygiene**: Use strong passwords, avoid sharing accounts, and separate admin accounts from day-to-day accounts.
    

---

✅ **Summary**:  
The `whoami /priv` command is a quick and powerful way to inspect the privileges granted to a user. Privileges vary depending on:

- **User role** (Standard User, Domain Admin, Backup Operator, etc.).
    
- **Group membership**.
    
- **Elevation level** (UAC context).
