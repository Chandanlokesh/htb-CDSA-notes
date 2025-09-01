![title logo](../attachments/Pasted%20image%2020250806181351.png)

## SIEM Definition & Fundamentals

- **SIEM** (security information and event management) like security control room form computers and networks
- it collects **logs** form all systems and watches for suspicious activity and alerts security staff
- helps in collects logs, analyzes data, generates alerts, incident handling, reports and dashboards
- SIEM = SIM + SEM
- this is how it works (Collects Logs -> Normalize Data -> Correlate events (patterns matching)-> generate alerts -> security analysts investigate )

**SIEM for business requirements**
- Log aggregation and normalization
- threat alerting
- adding context to the logs
- compliance

---
---
## Introduction To The Elastic Stack

The **Elastic Stack** (also called the **ELK Stack**) is a set of open-source tools that work together to **collect, store, search, and visualize data**—especially logs and events.

**components**
- **Elasticsearch**
	- its a search engine + database
	- it stores the logs an make them searchable
- **Logstash**
	- acts as the pipeline
	- transforms row unstructured data form different sources to structured that can be easily read by elasticsearch
	- the collected and transformed data is send to elasitchsearh
- **Kibana**
	- a dashboard & visualization tool
	- we can search, visualize and analyze the data
- **Beats**
	- lightweight agents installed on machines 
	- this will help to collect the logs form different sources form the end points like file, process, logon related data
	- the collected data is sent to logstash or elasticsearch

`Beats → Logstash → Elasticsearch → Kibana`

`Beats → Elasticsearch → Kibana`

![elk stack](attachments/Pasted%20image%2020250807225814.png)

- kibana use its language for query (KQL)

syntax
```
field:value

example

event.code:4625
```

[event codes encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4625)

[KQL docs](https://www.elastic.co/docs/explore-analyze/query-filter/languages/kql)

**ECS is a standard set of field names** used in the Elastic Stack to make data **consistent**, **searchable**, and **correlatable** across all data sources.

> Think of ECS as a “common language” that all logs (Windows, Linux, network, cloud, etc.) speak in Elastic.

`winlog.event_id:4625 AND winlog.event_data.SubStatus:0xC0000072`
we can use in ECS

`event.code:4625 AND winlog.event_data.SubStatus:0xC0000072`

- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/ecs-reference.html)
- [Elastic Common Schema (ECS) event fields](https://www.elastic.co/guide/en/ecs/current/ecs-event.html)
- [Winlogbeat fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-winlog.html)
- [Winlogbeat ECS fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-ecs.html)
- [Winlogbeat security module fields](https://www.elastic.co/guide/en/beats/winlogbeat/current/exported-fields-security.html)
- [Filebeat fields](https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields.html)
- [Filebeat ECS fields](https://www.elastic.co/guide/en/beats/filebeat/current/exported-fields-ecs.html)

#### Questions

1. Navigate to http://[Target IP]:5601, click on the side navigation toggle, and click on "Discover". Then, click on the calendar icon, specify "last 15 years", and click on "Apply". Finally, choose the "windows*" index pattern. Now, execute the KQL query that is mentioned in the "Comparison Operators" part of this section and enter the username of the disabled account as your answer. Just the username; no need to account for the domain.
`anni`

2. Now, execute the KQL query that is mentioned in the "Wildcards and Regular Expressions" part of this section and enter the number of returned results (hits) as your answer.
`8`

---
---
## SOC Definition & Fundamentals

- A **Security Operations Center (SOC)** is a centralized team responsible for:
    - **Continuous monitoring**
    - **Detecting, analyzing, and responding** to cybersecurity incidents
- SOC teams use:
    - **SIEM**, **IDS/IPS**, **EDR** tools
    - **Threat Intelligence**
    - **Threat Hunting**

#### Soc Roles and responsibilities 

|Role|Responsibilities|
|---|---|
|**SOC Director**|Strategic oversight, staffing, budgeting|
|**SOC Manager**|Manages operations, escalations, inter-team coordination|
|**Tier 1 Analyst**|Monitors alerts, does initial triage, escalates|
|**Tier 2 Analyst**|Investigates alerts, finds trends, develops responses|
|**Tier 3 Analyst**|Handles complex threats, leads threat hunting|
|**Detection Engineer**|Creates & refines detection rules (SIEM, EDR, IDS)|
|**Incident Responder**|Forensics, containment, and system recovery|
|**Threat Intel Analyst**|Tracks threat landscape, supports proactive defense|
|**Security Engineer**|Builds/maintains security tools & infrastructure|
|**Compliance & Governance**|Ensures policy, regulation, and audit alignment|
|**Awareness & Training Coordinator**|Runs security training for staff|

#### SOC Analyst Tier Breakdown

- **Tier 1** – _First responders_: Alert triage, prioritize, escalate
- **Tier 2** – _Investigators_: Deep analysis, trend detection, incident response
- **Tier 3** – _Hunters_: Complex threats, threat hunting, tool tuning, R&D

#### SOC Maturity Levels

**SOC 1.0 – Traditional / Basic**
- Focused on **network/perimeter**
- Tools aren't integrated (siloed alerts)
- Mostly reactive
- Some orgs still operate at this level 😬

**SOC 2.0 – Intelligent SOC**
- **Integrated tools** with **threat intelligence**
- **Correlated events**, anomaly detection
- Uses **Layer 7 analysis** for "low and slow" attacks
- Focus on:
    - Pre-event: Patch, config, risk management
    - Post-event: Forensics, lessons learned
    - Real-time detection with **situational awareness**

**SOC 3.0 – Cognitive SOC**
- Introduces **machine learning**, **AI**, and **automation**
- Bridges gap between **business and security**
- Adaptive response, learns from past incidents
- Goal: **Smarter, faster decision-making**
- Focused on **maturity**, **collaboration**, and **continuous learning**

#### Questions 
1. True or false? SOC 2.0 follows a proactive defense approac
`True`

---
---
## MITRE ATT&CK & Security Operations

- [MITRE ATT&CK](https://attack.mitre.org/)
- A global knowledge base of how hackers actually attack systems
- ATT&CK = **Adversarial Tactics, Techniques, and Common Knowledge**

#### structure of MITRE ATT&CK
- **Tactics** (columns) the attackers goal **the why**
- **Technique** (rows) specific methods attackers use to achieve that goal **the how**
- **sub technique** detailed variations of a technique
- **Procedure (TTPs)** real world examples of attackers using these techniques

#### Types of ATT&CK Matrices 
1. **Enterprise** -> windows, linux, macos,azure, aws ...
2. **Mobile** ->android, ios attacks
3. **ICS** -> (industrial control system) -> Attacks on power plants, factories etc

---
---
## SIEM Use Case Development

### SIEM Use Case – Overview

- SIEM use cases detect specific security events/behaviors.
    
- Range from simple (e.g., failed logins) to complex (e.g., ransomware outbreak).
    
- Example: 10 failed logins in 4 min → correlated into “Brute Force” alert.
    

---

### Use Case Development Lifecycle

#### Requirements

- Define detection goal (e.g., brute force detection).
    
- Source: customer, analyst, internal request.
    
- Specify trigger conditions (e.g., 10 failures in 4 min).
    

#### Data Points

- Identify all login points (Windows, Linux, VPN, apps).
    
- Verify log sources capture user, timestamp, source, destination.
    

#### Log Validation

- Ensure logs include: user, timestamp, source, destination, hostname, app name.
    
- Test across all auth types: local, web, app, VPN, OWA.
    

#### Design & Implementation

- Define **Condition**, **Aggregation**, **Priority**.
    
- Example: 10 failures / 4 min → aggregate per user → MEDIUM priority.
    

#### Documentation (SOP)

- Include: conditions, aggregation, priorities, escalation matrix.
    

#### Onboarding

- Test in dev before prod.
    
- Tune to reduce false positives.
    

#### Periodic Update / Fine-Tuning

- Analyst feedback → update rules.
    
- Maintain whitelist and refine logic.
    

---

### Use Case Build Guidelines

- Align with needs/risks.
    
- Map to **Kill Chain** / **MITRE ATT&CK**.
    
- Define **Time to Detect** (TTD) & **Time to Respond** (TTR).
    
- Maintain SOPs, Incident Response Plans (IRP).
    
- Set SLAs/OLAs for alert handling.
    
- Keep audit trail of alerts and response.
    
- Document logging coverage and rule triggers.
    
- Maintain a case management knowledge base.
    

---

### Example – MSBuild Started by Office App (High Severity)

- **Risk**: Adversaries execute MSBuild via Word/Excel → malicious payload.
    
- **Why**: LoLBins technique (Living-off-the-land binaries).
    
- **MITRE Mapping**:
    
    - Defense Evasion (TA0005) → T1127, T1127.001
        
    - Execution (TA0002)
        
- **Priority**: HIGH (depends on environment).
    
- **Detection Fields**:
    
    - `process.name`
        
    - `process.parent.name`
        
    - `event.action`
        
    - machine name, user name, recent activity
        
- **SOP**: Investigate user machine, collect SIEM logs, AV logs, proxy logs.
    
- **False Positive Tuning**: Whitelist dev machines and known parent processes.
    

---

### Example – MSBuild Making Network Connections (Medium Severity)

- **Risk**: MSBuild connects to remote IPs (possible C2).
    
- **Priority**: MEDIUM (legit MS IPs possible).
    
- **MITRE Mapping**: Execution (TA0002).
    
- **Detection Fields**:
    
    - `process.name = msbuild.exe`
        
    - `destination.ip` reputation check
        
- **Tuning**: Whitelist known MS update servers, dev systems.

---
---

## SIEM Visualization Example 1: Failed Logon Attempts (All Users)


![elastic dashboard](attachments/Pasted%20image%2020250808171517.png)

1. a filter option that allows us to filter the data before creating a graph or before printing the data we need
2. we can select what kind of data we need
3. all the fields that are available in the data
4. how we want to see our data

#### making a dashboard

**Purpose**

Create a dashboard and table visualization in Kibana to show **failed logon attempts** across all users, and refine it based on SOC requirements.

**1. Dashboard Setup**
1. Go to: `http://[Target IP]:5601`
2. **Sidebar → Dashboard**
3. Delete existing `SOC-Alerts` dashboard.
4. Click **Create new dashboard** → **Create visualization**.

 **2. Initial Visualization Setup**
- **Time Range:**
    - Click calendar icon → Set **Last 15 years** → Apply.
- **Filters:**
    - Add filter:
        ``  event.code: 4625```
        (Windows failed logon attempts)
- **Index Pattern:**
    - Use:
        ``` windows*```
- **Field Search:**
    - Search for `user.name.keyword` (use `.keyword` fields for aggregations).
- **Visualization Type:**
    - Select **Table**.

**3. Table Configuration**
1. **Rows:**
    - Add: `user.name.keyword` (username)
    - (Will initially be ranked alphabetically, later changes to count-based).
2. **Metrics:**
    - Add: `Count`
3. **Add Another Row:**
    - Add: `host.hostname.keyword` (machine name)

**Result:** Table with 3 columns:
- **Username** (currently includes users + computers — will filter later)
- **Hostname**
- **Event count**

**4. Save Visualization**
- Click **Save and return** → Visualization appears in dashboard.
- Save dashboard

 **Refinements (SOC Manager Requests)**
**Changes Required**
- Clearer column names.
- Add **Logon Type**.
- Sort results.
- Exclude:
    - Usernames: `DESKTOP-DPOESND`, `WIN-OK9BH1BCKSD`, `WIN-RMMGJA7T9TC`.
    - Computer accounts.
- Only monitor **user accounts**

**Steps**
1. **Edit Visualization:**
    - Dashboard → Click **pencil icon** on visualization.
    - Click **gear icon** → **Edit lens**.
2. **Rename Columns:**
    - `Top values of user.name.keyword` → Change to clear name (e.g., "Username").
    - `Top values of host.hostname.keyword` → Change to "Hostname".
3. **Add Logon Type:**
    - Add row: `winlog.logon.type.keyword`.
4. **Sort Results:**
    - Sort by **Count** (descending).
5. **Exclude Specific Usernames:**
    - Add filter to exclude:
  ```
  NOT user.name: ("DESKTOP-DPOESND" OR "WIN-OK9BH1BCKSD" OR "WIN-RMMGJA7T9TC")
   ```
6. **Exclude Computer Accounts:**

    - Add KQL:
        ```
        NOT user.name: *$ AND winlog.channel.keyword: Security
        ```
        
        - `$` matches machine accounts ending with `$`.

 **Final Steps**
- Click **Update** after each filter change.
- Save visualization → Save dashboard.

**End Result**

- A clean, sorted table showing:
    
    - **Usernames**
        
    - **Hostnames**
        
    - **Logon Types**
        
    - **Failed logon attempt count**
        
- Excludes irrelevant accounts and noise.
---
---
## SIEM Visualization Example 2: Failed Logon Attempts (Disabled Users)


**Purpose**  
Monitor failed logon attempts (Event ID 4625) for all users from Windows logs in `windows*` index.

**Steps**

1. Go to `http://[Target IP]:5601` → Dashboard.
    
2. Remove `SOC-Alerts` dashboard if exists → Create new dashboard → Create visualization.
    
3. Set time range to **Last 15 years** → Apply.
    
4. Add filter: `event.id: 4625`.
    
    - KQL:
        
        ```
        event.code: 4625
        ```
        
    - Index pattern: `windows*`
        
5. Search for `user.name.keyword` to confirm field exists.
    
6. Select visualization type: **Table**.
    
7. Add Rows:
    
    - `user.name.keyword` (Username)
        
    - `host.hostname.keyword` (Machine name)
        
8. Add Metrics:
    
    - Count → total number of failed logons.
        
9. Table will have: Username | Machine name | Count.
    
10. Save visualization and dashboard.
    

**Refinements**

- Rename columns to descriptive names.
    
- Add `winlog.logon.type.keyword` (Logon Type).
    
- Sort results by count.
    
- Exclude unwanted usernames:
    
    ```
    NOT user.name: "DESKTOP-DPOESND" AND NOT user.name: "WIN-OK9BH1BCKSD" AND NOT user.name: "WIN-RMMGJA7T9TC"
    ```
    
- Exclude computer accounts:
    
    ```
    NOT user.name: *$ AND winlog.channel.keyword: Security
    ```

### ELK SIEM Visualization – Example 2: Failed Logon Attempts (Disabled Users)

**Purpose**  
Detect failed logon attempts where the account is disabled. These will always fail even if credentials are correct.

**Key Event IDs / Fields**

- Event ID: 4625 (Failed logon)
    
- `winlog.event_data.SubStatus: "0xC0000072"` → Disabled user logon attempt.
    

**Steps**

1. Go to `http://[Target IP]:5601` → Dashboard → Edit → Create visualization.
    
2. Add filters:
    
    ```
    event.id: 4625 AND winlog.event_data.SubStatus: "0xC0000072"
    ```
    
    - Index pattern: `windows*`
        
3. Confirm field: `user.name.keyword`.
    
4. Select visualization: **Table**.
    
5. Add Rows:
    
    - `user.name.keyword` (Disabled username)
        
    - `host.hostname.keyword` (Machine name)
        
6. Metrics: Count.
    
7. Final table: Disabled Username | Machine | Count.
    
8. Save visualization and add to dashboard.

---
---


## SIEM Visualization Example 3: Successful RDP Logon Related To Service Accounts


### Logic – Successful RDP Logon with Service Accounts

**Goal**  
Detect successful RDP logons using service accounts (accounts starting with `svc-`).

**Why**

- Service accounts usually have high privileges.
    
- They should **never** be used for RDP in normal environments.
    
- Could indicate credential misuse or compromise.
    

**Key Event ID**

- `4624` → Successful logon.
    

**Key Conditions**

- **LogonType** = `10` (RDP / RemoteInteractive).
    
- **user.name** starts with `svc-`.
    

**KQL Example**

```kql
event.code: 4624
AND winlog.logon.type: 10
AND user.name: "svc-*"
```

**Fields to Display**

- `user.name` → Service account used.
    
- `host.hostname` → Target machine.
    
- `source.ip` → IP address of RDP connection.
    
- `@timestamp` → Time of event.

---
---

## SIEM Visualization Example 4: Users Added Or Removed From A Local Group (Within A Specific Timeframe)


### Logic – Users Added or Removed from Local Administrators Group (Specific Timeframe)

**Goal**  
Detect when users are **added to** or **removed from** the local “Administrators” group within a defined time range.

**Why**

- Membership changes in the Administrators group can grant or revoke privileged access.
    
- Could indicate insider threat or account compromise.
    

**Key Event IDs**

- `4732` → Member added to a security-enabled local group.
    
- `4733` → Member removed from a security-enabled local group.
    

**Key Conditions**

- `group.name` = `"Administrators"`.
    
- `@timestamp` between `2023-03-05` and `now`.
    

**KQL Example**

```kql
(event.code: 4732 OR event.code: 4733)
AND group.name: "Administrators"
AND @timestamp >= "2023-03-05T00:00:00Z"
```

**Fields to Display**

- `winlog.event_data.MemberSid` → User added/removed.
    
- `group.name` → Group name (confirm “Administrators”).
    
- `event.action` → Addition or removal.
    
- `host.name` → Machine where change occurred.
    
- `@timestamp` → Time of event.


---
---
## The Triaging Process

### Alert Triaging – SOC Analyst Workflow

**Definition**  
Process of reviewing, prioritizing, and escalating security alerts to determine threat level and impact.

---

### Steps

#### Initial Alert Review

- Check alert metadata: timestamp, source/destination IP, affected systems, triggering rule.
    
- Review related logs (network, system, application) for context.
    

#### Classification

- Rate **severity**, **impact**, and **urgency** per org policy.
    

#### Correlation

- Cross-check with related alerts/events/IOCs.
    
- Query SIEM for relevant data.
    
- Use threat intel feeds for known patterns/malware.
    

#### Enrichment

- Add data: packet captures, memory dumps, file samples.
    
- Use sandboxes, threat intel sources, OSINT.
    
- Check affected systems for anomalies (connections, processes, file changes).
    

#### Risk Assessment

- Impact on critical assets and sensitive data.
    
- Compliance/regulatory implications.
    
- Likelihood of lateral movement or further compromise.
    

#### Contextual Analysis

- Criticality of affected systems.
    
- Security controls in place and potential bypass/failures.
    
- Regulatory and contractual obligations affected.
    

#### Incident Response Planning

- Document all details and IOCs.
    
- Assign IR team roles.
    
- Coordinate with other departments/vendors.
    

#### IT Operations Consultation

- Gather missing context (system changes, maintenance, misconfigurations).
    
- Confirm if false positive or expected activity.
    

#### Response Execution

- If benign → resolve and document.
    
- If suspicious → initiate incident response actions.
    

#### Escalation

- Triggered by:
    
    - Critical asset compromise.
        
    - Ongoing/advanced attack.
        
    - Widespread impact.
        
    - Insider threats.
        
- Notify higher-level teams/management.
    
- Share alert summary, impact, enrichment, risk.
    
- Escalate externally if required (law enforcement, CERT).
    

#### Continuous Monitoring

- Track situation and IR progress.
    
- Keep communication open with escalated teams.
    

#### De-escalation

- Lower escalation level when incident is contained.
    
- Share summary of actions, outcomes, lessons learned.
    
- Update procedures to address gaps.
    

---
---

## Skill Assessment

