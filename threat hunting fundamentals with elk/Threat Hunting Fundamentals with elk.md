![threathunting](../attachments/Pasted%20image%2020250812100047.png)
- human led hunting team looking for threats before alerts come . 
- often hypothesis driven and focused on finding threat that evade existing security tools
- the main goal is the reduce the dwell time in cyber kill chain

#### how threat hunting works
- identify high value assets - what's worth attacking 
- analyze likely TTP - how would attacker go after these
- hunt for artifacts - look for traces (unusual ps command, suspicious logins...)
- compare the baseline - what is normal in the env and what not
- validate findings - confirm whatever we got is malicious 

```
incident handling is reactive - responding when something has already happend

threat hunting is proactive - looking for threat before they cause an incident but these two works together in multiple phases 
```

- **Hunters** find footprints.
- **Intel analysts** monitor known poacher activity.
- **Responders** intercept poachers.
- **Forensics** examines traps and tools.
- **Data scientists** track animal migration patterns.
- **Engineers** build better fences.
- **Network analysts** monitor movement across borders.
- **Manager** coordinates everyone.

#### When should we hunt
- **new adversary or vulnerability discovered** 
	- a new hacking group targeting or fresh vulnerability in software we use 
- **new IOCs linked to known adversary**
	- Threat intel may release fresh indicators of compromise (IPs, domains, file hashes)
- **multiple network anomalies detected**
	- few unusual activity is ok but several anomalies at once means some thing is wrong
- **during an incident response (IR)**
	- while IR is fixing a confirmed security incident hunters should scan the wider env
- **periodic proactive hunts**
	- even without an alert or trigger, regular hunt catch stealthy threats before they cause damage 

#### Risk assessments and threat hunting

```
risk assessment - finding out where you are most vulnerable and what chold hunt you the most

threat hunting - actively looking for bad guys in those high-risk areas

risk assessment will guides where and how you hunt without that wandeing around network hopind to find something
```

how risk assessment helps threat hunting 
- prioritizing hunts
- understanding the threat landscape
- highlighting vulnerabilities 
- informing threat intelligence use 
- anticipation likely breaches makes IR faster and more accurate
- finding risk assessment with good security tools/configurations

#### Questions

1. Threat hunting is used ... Choose one of the following as your answer: "proactively", "reactively", "proactively and reactively".
`proactively and reactively`

2. Threat hunting and incident handling are two processes that always function independently. Answer format: True, False.
`False`
3. Threat hunting and incident response can be conducted simultaneously. Answer format: True, False.
`True`

---
---

### The Threat Hunting process 

#### 1. setting the stage (Preparation)
- understand what threats matters to your organization 
- identify critical assets 
- Make sure _logging is enabled_ everywhere
- Ensure tools like **SIEM, EDR, IDS** are working and collecting data.
- Stay updated on _current threat intelligence_.
If you’re a bank, you’d focus on detecting ATM malware or SWIFT fraud, not point-of-sale attacks (more relevant to retail). You might configure your SIEM to ingest logs from core banking applications and EDR agents on teller machines.

#### 2. formulating Hypotheses
- This is **making an educated guess** about where an attacker might be hiding.
- APT X is exploiting the Log4j vulnerability on our public web server to install a backdoor.” This is testable because you can check logs for suspicious payloads and outbound connections.
#### 3. Designing the hunt
- This is your **treasure map planning** stage. You decide _which clues to look for_, _where to search_, and _how to search_.
#### 4. data gathering and examination
- hear we will look for the evidence . collect relevant logs  and telemetry
- use analysis techniques 
#### 5. Evaluating findings and testing hypotheses 
- so after finding some evidence we need to validate it . understand attacker behavior and impact identify systems
#### 6. mitigating  threats
- isolate infected systems, remove malware, patch vulnerabilities, adjust configurations
#### 7. After the hunt
- Think of this as **writing the expedition report** so the next explorer knows what you learned. and improve the rules 
#### 8. continuous learning and enhancement
- the hunting is never done attackers adopts so we must review what worked and what didn't , add new tools  methods
---
#### Emotet example with threat hunting 

[emotet malware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-280a)

#### 1. setting the stage (Preparation)
- researched on emotets TTPs form some resources or news or reports
- understood how it works and everything about that and we analize where can we see this kind of things
- comes form email, and it spread whole network using bruteforce attack, targets everything , every time it accessed it will change the code littel bit so its harder to detect 
#### 2. formulating Hypotheses
- Used known **IoCs** & patterns from past Emotet attacks
- make a hypotheses where it can be seen form who's computer that can be easly seen and what are the area they can spread
#### 3. Designing the hunt
- pick data sources : email logs, network logs, endpoints 
- define proper queries like subject lines, attachments, c2 traffic patterns
#### 4. data gathering and examination
- Pulled logs from chosen sources.
- Emails with suspicious attachments, traffic to known emotet c2 servers
#### 5. Evaluating findings and testing hypotheses 
- Found clusters of suspicious emails → **Hypothesis confirmed**.
- Found outbound traffic to C2 → infection likely active.
- Investigated depth of compromise and affected systems.

#### 6. mitigating  threats
- isolate infected sys, remove emotet from endpoints, secured email, blocked known c2 communications
#### 7. After the hunt
- document everything , update detection rules, shared new iocs internally and externally 

#### 8. continuous learning and enhancement
- reviewed what worked and what didn't
- incorporated new detection methods like behavioral analytics 
- kept up with latest emotet tactics

---
---

### threat hunting glossary

#### 1. Adversary
- the bad guys who have goals and they will try to bypass the defenses to get them
- cyber criminals, insider threats, hackivists, state sponsored
#### 2. APT (advanced persistent threat)
- they are highly patient attackers they use proper planning and resources use to attack and they most often work in groups with highly intelligent people 
- they will keep coming back until they succeed
#### 3. TTPs (Tactics, Techniques and procedures)
- **tactics** the why ?
- **Techniques** the how in general
- **procedures** the step by step recipe
#### 4. Indicator
- a clue in the digital crime scens can be any thing ip, hash etc with context 
- without context its just noise
- finding a shoue in trash dump is not suspicious but if the criminal shoue matches with that is the context we need
#### 5. Threat 
- made of 3 main thing
- **intent** - they want to attack you
- **capability** - they can attack you 
- **Opportunity** - yove left the door open
#### 6. Campaign 
- a series of related attacks shares the same TTPs aiming for similar goals . this shows the attackers are persistence and strategy 
#### 7. IOCs (indicators of compromise)
- its a digital fingerprints of malicious activity . like clues that tells something is happened 
#### 8. Pyramid of pain
- this will help out IOCs to rank

![pyramid of pain](../attachments/Pasted%20image%2020250812225546.png)

 [Intel-Driven Detection and Response to Increase Your Adversary’s Cost of Operations.](https://rvasec.com/slides/2014/Bianco_Pyramid%20of%20Pain.pdf)
- **hash values**
	- easy for attacker to change. like if he changes a single line then also the hash value is changed 
- **IP addresses**
	- if they use vpn or others they can easy to get out away form our eyes
- **Domain names**
	- they can use compromised subdomains or change the name of the domain trick user to access the site 
- **network host artifacts**
	- **network artifacts** these are the footprint in the snow
	- if we follow the movements of the attack form where attacker came and where he went then we can follow the attack he use what tools he may have used
	- **Host artifacts** fingerprints on the doorknobs inside the house this shows exactly what the attacker touched  
	- we can see what he has done to our systems registry key creation, a suspicious .exe
- **Tools**
	- software adversaries use malware, scripts, exploits c2 frameworks
- **TTPs**
	- TTPs are the **criminal’s full playbook** — their overall strategy, how they act, and the exact steps they take.

#### 9. Diamond model of intrusion analysis 

![](../attachments/Pasted%20image%2020250812231513.png)

used to systematically understand, analyze, and respond to cyber intrusions by focusing on key elements and their relationships.
its like helps to make decision on what we have and what we can do 

**Adversary**
- the individual, group or organization responsible for the intrusion 
- who did the attack

**Capability**
- the tools, TTPs used to execute the intrusion 
- how did they do it

**Victim**
- The target of the attack (person, organization, or system).
- whom did they attack

**Infrastructure**
- Physical and virtual systems/resources used to launch, control, and maintain the attack.
- what was used to perform the attack 

https://www.youtube.com/watch?v=w8mEG52tfsY

---
----

### Cyber Threat Intelligence Definition (CTI)

- it gives actionable info about potential or ongoing cyber threats

**Four fundamental principles make CTI an integral part of our cybersecurity strategy**

![principle](../attachments/Pasted%20image%2020250813181920.png)

- **Relevance** we must ensure the organization using the safe systems . there will be lot of info about the hacks, vulnerability but we must focus on what over organization is required
- **Timeliness** try to patch newly disclosed vulnerability or info old data may not be not accurate for know . shift the info got form the CTI team to defense team
- **Actionability** the data we are giving to the defense team that should be actionable it should not be some noise
- **Accuracy** before disseminating any intelligence it must be verified for accuracy it will be loss of time resources 
---
#### Threat intelligence 
- predict what might happen
- understanding the enemy's playbook
- where, when, how and why they will attack
#### Threat hunting 
- find the attackers already in or conform they have sneaked in
- investigating suspicious signs 

---

CTI should understanding of threats to our organization and partner entities, potential insights into our organization network and awareness of potential problems that may gone unnoticed

nformation is compiled, it transforms into intelligence. This intelligence can then be classified into three different categories,

![](../attachments/Pasted%20image%2020250813191201.png)

`Strategic Intelligence` is characterized by
- **Audience:** Executives, senior leadership.
- **Goal:** Align threat insights with _business risks_ and decision-making.
- **Focus:** Long-term adversary objectives, motivations, and high-level patterns.
- **Answers:** **Who** is the adversary? **Why** are they targeting us?

`Operational Intelligence` is characterized by
- **Audience:** Mid-level management, SOC leadership.
- **Goal:** Understand the _active operations_ of an adversary.
- **Focus:** Adversary TTPs in specific campaigns, attack phases, and tools used.
- **Answers:** **How** will they attack? **Where** will they attack?

`Tactical Intelligence` is characterized by
- **Audience:** SOC analysts, IR teams, threat hunters.
- **Goal:** Provide _technical, actionable data_ to stop or detect threats now.
- **Focus:** Indicators of Compromise (IOCs), signatures, artifacts.
- **Answers:** **What exactly** should we block, detect, or monitor right now?

---

#### How to Read and Use a Tactical Threat Intelligence Report
1. **Understand the Story First** before diving into the technical details get the big picture
2. **Find and Group the IOCs** 
3. **Learn the attack steps** TTPs 
4. **Check and Validate the IOCs**
5. **Add IOCs to Your Security Tools** add that into firewalls, EDRs/ Antivirus etc
6. **Start Threat Hunting** dont wait for the alert start looking 
7. **Keep Watching and Learning**

#### questions 

1. False
2. Reach out to the Incident Handler/Incident Responder
3. Provide further IOCs and TTPs associated with the incident
4. provide insight into adversary operations

---
---

### Hunting For Stuxbot

- Stuxbot is a cybercriminal group
- started phishing attacks and they dont target specific companies 
- they seem focused on spying , they are not trying to steal money, demand ransom or sell stolen business secrets 
- they target **Microsoft windows**
- They could take full control of your computer.
- They could gain control over your entire network/domain.

#### attack sequence

![](../attachments/Pasted%20image%2020250813195023.png)

**`Initial Breach`**
email that includes a link leading to a OneNote file that onenote file is in mego.io or some thing

![](../attachments/Pasted%20image%2020250813195215.png)

the onenote file will have a **hidden button** that button will trigger a **Batch file** that will be stage 0 the batch file will downloads **powershell scripts** 

**`RAT Characteristics`**
The malware is a **Remote Access Trojan (RAT)** — basically a “remote control” for your PC
they can add new features to spy on the target like screen capture, [Mimikatz](https://attack.mitre.org/software/S0002/), teals password from memory

**`Persistence`**
They make sure the RAT survives reboots/ like they will drop an .exe on the disk that runs every time the sys starts

**`Lateral Movement`**
Once inside one computer, they try to move to others in the network using
1. **PsExec** — a Microsoft tool for running commands on remote systems.
2. **WinRM** — Windows Remote Management

**`Indicators of Compromise (IOCs)`**

**malicious onenote file**
```
https://transfer.sh/get/kNxU7/invoice.one
https://mega.io/dl9o1Dz/invoice.one
```

**PowerShell scripts (stage 0 payloads)**
```
https://pastebin.com/raw/AvHtdKb2
https://pastebin.com/raw/gj58DKz
```

**Command & Control servers** (where RAT phones home)
```
91.90.213.14:443
103.248.70.64:443
141.98.6.59:443
```

**Malicious file hashes (SHA256)**
```
226A723FFB4A91D9950A8B266167C5B354AB0DB1DC225578494917FE53867EF2
C346077DAD0342592DB753FE2AB36D2F9F1C76E55CF8556FE5CDA92897E99C7E
018D37CBD3878258C29DB3BC3F2988B6AE688843801B9ABC28E6151141AB66D4
```

### Hunting

```
http://[Target IP]:5601

15 years

Please also specify a `Europe/Copenhagen` timezone, through the following link

`http://[Target IP]:5601/app/management/kibana/settings`.
```

The Available Data

- `Windows audit logs` (categorized under the index pattern windows*)
- `System Monitor (Sysmon) logs` (also falling under the index pattern windows*, more about Sysmon [here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon))
- `PowerShell logs` (indexed under windows* as well, more about PowerShell logs [here](https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html))
- `Zeek logs`, [a network security monitoring tool](https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields-zeek.html) (classified under the index pattern zeek*)

Our organization is relatively small, with about 200 employees primarily engaged in online marketing activities, thus our IT resource requirement is minimal.

all our company devices are managed via Active Directory Group Policy Objects (GPOs).

`The Task`
Our task centers around a threat intelligence report concerning a malicious software known as "Stuxbot". We're expected to use the provided Indicators of Compromise (IOCs) to investigate whether there are any signs of compromise in our organization.

`The Hunt`

The report indicates that initial compromises all took place via "invoice.one" files.

![](../attachments/Pasted%20image%2020250813221503.png)

![](../attachments/Pasted%20image%2020250813222109.png)

![](../attachments/Pasted%20image%2020250813222211.png)
