
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