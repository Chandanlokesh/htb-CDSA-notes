![Incident Handling](../attachments/Pasted%20image%2020250805174302.png)
## Incident Handling

- Incident Handling is like a fill station we hope we never need it but when the fire starts,it can save the entire organization
- A structured process to **manage and respond** to security incident in a computer or network

>**Event**
>	any action in a system/network

>**Incident**
>	an event that has a negative consequence 

### Good IH should cover / scope of IH
- Detection and identification of suspicious activity
- Containment : stop if form spreading 
- Eradication : remove the root cause
- Recovery : restore to normal operations
- Document what happened and what should we do to prevent it form happening next time  

> **Industry standard: NIST computer security incident handling guide**
> - National Institute of Standards and Technology
> - it provides practical guidelines to respond to incident effectively and efficiently 
> - [NIST's Computer Security Incident Handling Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf).

---
---
## Cyber Kill Chain

- cyber kill chain is a model created by Lockheed Martin to describe the stages of a cyberattack from start to finish
- As a defender we should try to stop attackers as early in the chain as possible, because the further they progress. the more damage they can cause

![Incident Handling](../attachments/Pasted%20image%2020250805182611.png)

- `Reconnaissance` 
	- planning & info gathering
	- attacker choose a target and collects information 
	- Passive recon - social media, company websites, job portals or many other resources
	- Active recon - Port scans, Probing web apps, identifying IPs etc
	- ex:Checking a job ad that says, _“We use Cisco Firewalls and Windows Server 2019.”_ → Attackers now know what tech stack to exploit.
- `Weaponization`
	- attackers creates a malicious payload tailored for the target
	- ex: creating a malware-laced word document that avoids detection by ms defender
- `Delivery`
	- delivering the payload to victim 
	- ex:Email titled _“Invoice Attached”_ with a malicious PDF, USB stick left in the office parking lot .many other ways
- `Exploitaiton`
	- the payload that we have sent should be triggered the payload
	- ex: User double-clicks the attachment,  exploits uses a vulnerability to execute automatically 
- `Installation`
	- establishing foothold in the target machine to maintain access
	- ex: installing a remote access trojan (RAT) to control the victim's PC even after reboots
- `Command & Control (C2)`
	- attackers are establishes communication with the compromised machine
	- ex: attackers can instructs from out-side what to do inside the compromised machine 
- `Actions on Objective`
	- attackers executes the final mission 
	- ex: data theft, full domain compromise, ransomware deployment etc

> our objective is to stop an attacker form progressing  further up the kill chain, ideally in one of the earliest stages

#### Questions

`Disclaimer: Some answers are tweaked or hidden — learn it, don’t just copy it`

In which stage of the cyber kill chain is malware developed?
`we@p0n1ze`

---
---
## Incident Handling Process Overview

- we got to know the attack lifecycle we can know anticipate an attacker's moves. but to respond effectively for that we need a structured process 

![Incident Handling](../attachments/Pasted%20image%2020250805193808.png)


- `Preparation`
	- building the defenses and processes before an incident
	- like train staff, deploy monitoring tools, regular backups and recoverys
- `Detection & Analysis`
	- spot suspicious events - figure out if they're real incident
	- like monitor logs, alerts and anomalies , analyze malware samples ...
- incident handlers spends most of their time in Preparation + Detection and analysis
- `Containment, Eradication & Recovery`
	- stop the attack, remove it and restore normal operatons
	- **Containment** 
		- isolate infected machines
		- Block malicious IPs or accounts
	- **Eradication**
		- Remove malware/backdoors/rootkits
		- Patch vulnerabilites
	- **Recovery**
		- rebuild systems from backups
		- test to ensure they're clean
	- must fully handle all infected systems
- `Post-incident Activity`
	- after the fire is out, figure out what went wrong so it doesn't happens again
	- write an incident report, review what worked & what didn't, update the checklist, patch systems and train staff

`Note : while cleanign up, we discover more infected machine -> go back to detection/containment. this is a loop not a stright line`

#### Questions

`Disclaimer: Some answers are tweaked or hidden — learn it, don’t just copy it`

True or False: Incident handling contains two main activities. These are investigating and reporting.
`no`

---
---
## Preparation Stage (Part 1)

- think a cricket team is showed up on game day without training, preparation or fitness they'll lose no matter how talented they are
- Good Preparation = faster detection + smaller impact when incident happen
- there is two main objective of preparation
	- Build incident handling capability (organization has the people, processes and tools to handle incidents)
	- Prevent & Protect against IT Security Incident by building strong defence

#### Preparation Prerequisites 
- there is four key things
	- skilled incident handling team members (in-house, outsourced)
	- trained workforce (everyone should have basic understanding on cyber sec)
	- clear policies and documentation (written guidelines on what to do, who does it what, when to do)
	- tools  (without proper tools even skilled team are blind make sure to cover detection tools, analysis tools and incident management platforms)

#### Clear Policies & Documentation 
- what documentation should contain
	- **Team & Contacts:** Keep updated contact info for IH team, legal, IT, PR, law enforcement, ISPs, and vendors.
	- **Policies & Plans:** Have a clear incident response plan and rules for sharing info safely.
	- **System Baselines:** Store clean “golden images” and standard system/network setups.
	- **Network Diagrams:** Maintain maps of your network for quick reference.
	- **Asset Inventory:** Track all company devices, systems, and their owners.
	- **Privileged Accounts:** Keep special admin accounts disabled until needed for incidents, then reset after use.
	- **Emergency Purchases:** Allow quick buying of tools/resources without long approvals.
	- **Forensic Cheat Sheets:** Prepare ready-made checklists for investigation steps.
	- **Legal Compliance:** Know reporting rules (e.g., GDPR requires breach reports within 72 hrs).
	- **Live Documentation:** During incidents, log who did what, when, where, why, and how.

#### Tools
- essential tools and equipment
	- **Forensic Workstations / Laptops** : Extra laptops or dedicated forensic PCs for investigations.Used to collect disk images, logs, and test malware safely (antivirus usually disabled here).
	- **Digital Forensic Tools** :For acquiring and analyzing disk images.
	- **Memory Capture & Analysis Tools** : Memory Capture & Analysis Tools
	- **Live Response Tools** To collect data (running processes, network connections) from a live system.
	- **Log Analysis Tools** To sift through massive logs for signs of compromise.
	- **Network Capture & Analysis Tools** To inspect traffic for malicious activity.
	- **Physical Equipment** network cables switches , write blockers etc ..
	- **IOC (Indicator of Compromise) Tools** Create and search IOCs (like malicious IPs, file hashes) across the network.
	- **Chain of Custody Forms** To legally track who handled evidence and when.
	- **Encryption Software** To securely store collected evidence.
	- **Ticket Tracking System** To manage and track incident tasks.
	- **Secure Facility** Safe, controlled location for storing evidence and conducting investigations.
	- Independent Incident Handling System

**jump Bag** = ready to go kit with all essential tools (instead of scrambling for tools, grab the bag and respond imediately)

#### Questions

`Disclaimer: Some answers are tweaked or hidden — learn it, don’t just copy it`

What should we have prepared and always ready to 'grab and go'?
`j bag`

True or False: Using baselines, we can discover deviations from the golden image, which aids us in discovering suspicious or unwanted changes to the configuration.
`yes`

---
---

## Preparation Stage (Part 2)

- some protective measures with high impact
	- **DMARC (Domain based message authentication, Reporting and conformance)**
		- In email, this fake‑out is called **spoofing**, and attackers often use it to trick victims into clicking malicious links or paying fake invoices.
		- DMARC is built on this **SPF(sender policy framework)** checks if the sending server is allowed, **DKIM(Domainkeys identified mail)** check if the email hasn't been tampered with, **DMARC** = final check → if the name on the ticket doesn’t match, you don’t board the plane.
	- **endpoint & server hardening**
		- protecting endpoints = stopping attackers before they get a foothold
		- **CIS** (center for internet security) or **microsoft baselines** as the foundation its like a standard recipe so we dont miss key ingredients 
		- **Disable LLMNR/NetBIOS :** these protocols can be abused for credential theft
		- **Implement LAPS (local admin password solution) & Remove Admin Privileges :** regular users should not have admin rights it will stops attackers form spreading laterally
		- **Restrict PowerShell (ConstrainedLanguage Mode)**
		- **Enable ASR (Attack Surface Reduction) Rules** blocks risky behaviors
		- **Application Whitelisting** If full whitelisting isn’t possible: block execution from risky folders (`Downloads`, `Desktop`, `AppData`). and blocking scripts like .bat, .js, .cmd ...
		- **use Host based firewalls** block workstation to workstation
		- **Deploy an EDR (Endpoint Detection & Response) solution** like microsoft defender with amsi (anti-malware scan interface)
	- **multi-factor authentication (MFA) & Privileged Access Management (PAM)**
	- **Vulnerability scanning** Perform continuous vulnerability scans of your environment and remediate at least the "high" and "critical" vulnerabilities that are discovered.
	- **User Awareness training** 
	- **Network Protection**
		- without network segmentation a breach in one machine can spread everywhere 
		- IDS/IPS intrusion detection and prevention system 
		- device access control only allows approved devices on the network 
	- **Security Monitoring Tolls**
	- **Active Directory (AD) Training**
		- Spot misconfigurations & vulnerabilities before attackers do
		- Look at AD **like an attacker would** (offensive mindset).
	- **Having purple team knowledge will be great**

#### Questions

`Disclaimer: Some answers are tweaked or hidden — learn it, don’t just copy it`

1.  What can we use to block phishing emails pretending to originate from our mail server?
`DM@Rc`

2.  True or False: "Summer2021!" is a complex password.
`yes`
---
---
## Detection & Analysis stage (Part 1)

- Detection = **spotting suspicious activity**.
- Analysis = **figuring out if it’s a real threat or a false alarm**.

**Source of Detection**
- Employees noticing abnormal behavior
- security tools raising alerts 
- Threat hunting activities
- third party notification (another company warns us of a breach)

**Layered Detection Approach**
onion with layers of defense 
- Network Perimeter (firewall, IDS/IPS, DMZ)
- Internal Network (local firewall, host IDS/IPS)
- Endpoint (Antivirus, EDR)
- Applications (apps and services logs)

### initial investigation 
- when we see smoke in a building before calling the entire fire department we want to check is it a kitchen fire or a candle or just burnt toast 

**Key information to collect**
- date and time (when and who)
- how detected (alerts, employee report, ...)
- type of incident (phishing, malware...)
- impact systems (which and how many dives , who owns them)
- current status (still ongoing or has abnormal activity stopped)
- system details (physical location, os, IP address, host name ...)
- info of malware (if involved)

**example of incident timeline**

| Date       | Time      | Hostname    | Event Description               | Data Source        |
| ---------- | --------- | ----------- | ------------------------------- | ------------------ |
| 09/09/2021 | 13:31 CET | SQLServer01 | Hacker tool "Mimikatz" detected | Antivirus Software |

### Incident Severity & Extent Questions

Severity analysis ensures you use the **right level of response** — not overkill, not underkill

**key questions to assess severity**

- what is the exploitation impact (how much damage can this cause)
- what are the exploitation requirements (Does it need insider access, or can anyone exploit it remotely?...)
- Can business-critical systems be affected? (If yes → priority skyrockets.)
- Are there suggested remediation steps? (Do we know how to fix it quickly, or is it unknown?)
- How many systems have been impacted? (More systems = more urgency.)
- Is the exploit being used in the wild? (If attackers are already exploiting it globally → red alert.)
- Does the exploit have worm-like capabilities? (Worms spread automatically without human help.)

### Incident Confidentiality & Communication

Handling an incident is like dealing with a **crime scene inside your company**.
- **Need-to-Know Only** → Share details only with people directly working on the case or legally required.
- **Watch Out for Insider Threats** → The attacker could be an employee.
- **External Updates** → Customers, law enforcement, and media updates go through **one authorized person** (usually with legal team guidance).
- **Regular updates** → so leaders know the status and can make decisions.
- **One Point of Contact** (Incident Manager) → avoids mixed messages.

#### Questions

`Disclaimer: Some answers are tweaked or hidden — learn it, don’t just copy it`

1. True or False: Can a third party vendor be a source of detecting a compromise?
`yes`

---
---
## Detection & Analysis Stage (Part 2)

*Find how they got in, what they did, and which systems were touched_ so we can block their path permanently.*

### The Investigation Cycle

![Incident Handling|400](../attachments/Pasted%20image%2020250805234359.png)

1. **create and use IOCs**
	- IOCs (Indicators of Compromise)=  clues of compromise
	- tools : openioc/yara, mandiant IOCs editor
	- if we know this are all the different abnormal behavior and if we faced some incident we can make alerts for that
2. **Identify New Leads & Impacted Systems**
	- IOC scans may give **hits** → systems showing signs of compromise
	- but some hits are false positive so start with big and try to reduce and make it specific 
3. **Collect & analyze Date**
	- Live Response -> collect data while system is running
	- shut down and forensic analysis -> less common, risky because ram data is lost when power off some of the technique are disk forensics and memory forensics 

#### Questions

`Disclaimer: Some answers are tweaked or hidden — learn it, don’t just copy it`

1. During an investigation, we discovered a malicious file with an MD5 hash value of 'b40f6b2c167239519fcfb2028ab2524a'. How do we usually call such a hash value in investigations? Answer format: Abbreviation
`I0C`

---
---

## Containment, Eradication, & Recovery Stage

After the investigation, once we know **what happened** and **how it impacted the business**, we move into this stage to stop the attack, kick out the adversary, and safely restore operations.

#### Containment
Stop the spread of the attack while keeping evidence intact. must be coordinated across all system otherwise attacker may notice and change tactics

**short term containment**
- quick action with minimal changes to preserve forensic evidence 
- give time to plan remediation  & capture forensic images
- if shutdown is needed get business approval first
**Long term containment**
- stronger lasting actions for security 
- apply firewall rules, deploy host intrusion detection system ...
- keep stakeholder updated
#### Eradication 
- remove attacker completely
- activities like : delete malware form system, rebuild infected machines, restore clean backups ...
#### Recovery
- safely return to normal business operations 
- steps : check restored systems are working properly -> bring system back into production -> enable heavy monitoring since attack 
- watch for suspicious signs 

#### Questions

`Disclaimer: Some answers are tweaked or hidden — learn it, don’t just copy it`

1. True or False: Patching a system is considered a short term containment.
`no`

---
---

## Post-Incident Activity Stage

Document the incident, learn from it, and improve for the future.  
This stage usually happens **a few days after the incident**, once the final report is ready.

**final incident report answers key questions**
- What happened and when?
- How well did the team perform (plans, playbooks, policies, procedures)?
- Did the business provide info & support on time?
- What actions were taken to contain and eradicate the threat?
- What preventive steps can stop this in the future?
- What tools/resources are needed for better detection & analysis next time?

#### Questions

`Disclaimer: Some answers are tweaked or hidden — learn it, don’t just copy it`

1. True or False: We should train junior team members as part of these post-incident activities.
`yes`

