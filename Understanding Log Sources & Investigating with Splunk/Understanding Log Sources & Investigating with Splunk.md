![](../attachments/Pasted%20image%2020250905181823.png)
## introduction to splunk and SPL

![](../attachments/Pasted%20image%2020250905103421.png)


![](../attachments/Pasted%20image%2020250905103507.png)


`Forwarders (Data collection layer)`
collects and send machine data to indexers
- **Universal forwarder (UF)** 
	- lightweight agent, minimal resource use
	- collects and forwards data (no parsing)
- **Heavy forwarder (HF)**
	- parses and filters data before forwarding
	- has lot of filtering features only in enterprise version
- **HTTP Event Collector (HEC)**
	- collects data directly form apps via tokens 
	- sends data directly to indexers

`Indexers (data storage and search layer)`
- receive and store data in indexes (compressed raw data + index files)
- organize data into directories by age (buckets)
- handle search queries 

`Search Heads (search and use interaction layer)`
- coordinate and dispatch search jobs to indexers and merge results and present them to users
- provide UI for searching 
- allows creating knowledge objects (fields, tags macros ...) without altering raw data

`Managemant Components`
- **Deployment Server** → Manages forwarder configurations, distributes apps/updates.
- **Cluster Master** → Manages Indexer clusters (replication, search affinity).
- **License Master** → Manages Splunk license usage & compliance.

`Key components`
- **Splunk Web Interface** → GUI for search, dashboards, alerts, reports.
- **Search Processing Language (SPL)** → Query language to search, filter, analyze data.
- **Apps & Add-ons**
    - **Apps** → Complete solutions (dashboards, pre-configs, workflows).
    - **Technology Add-ons (TAs)** → Extend Splunk with extra field extractions, data collection configs, transforms, scripts.
    - Apps often **use one or more TAs**.
- **Knowledge Objects** → Customizations to enrich data:
    - Fields, tags, event types, lookups, macros, data models, alerts.


```
Forearders -> Indexers -> search Heads -> Users
```


### SPL (splunk processing language)

| **SPL Command / Concept**         | **Description**                                                                                                          | **Example Query**                                                                                                                                                                                                                | **Explanation**                                                                                                                                                                                                                                                                        |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Basic Searching**               | Search for keywords, phrases, or patterns in events.                                                                     | `search index="main" "UNKNOWN"` `index="main" "*UNKNOWN*"`                                                                                                                                                                       | First query searches for exact word **UNKNOWN**. Second query uses `*` as a wildcard to match **any word containing UNKNOWN**.                                                                                                                                                         |
| **Fields & Comparison Operators** | Filters events using fields and conditions. Operators: `=`, `!=`, `<`, `>`, `<=`, `>=`                                   | `index="main" EventCode!=1`                                                                                                                                                                                                      | Searches all events in **main index** where `EventCode` is **NOT equal to 1**.                                                                                                                                                                                                         |
| **fields**                        | Show or hide specific fields in results.                                                                                 | `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 \| fields - User`                                                                                                                                                      | Removes the `User` field from the output. (`fields` can **include** or **exclude** fields).                                                                                                                                                                                            |
| **stats**                         | performs statistical operations (count, avg, sum, min, max, distinct count, etc) on fields grouped by one or more fields | `index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 \| stats count BY _time, Image`                                                                                                                                        | Returns a table where each row = unique combination of `_time` and `Image`. The `count` column shows how many network connection events occurred for that process at that time. Supports many functions: `count`, `dc(field)`, `sum(field)`, `avg(field)`, `min(field)`, `max(field)`. |
| **table**                         | Displays results in a clean table format.                                                                                | `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 \| table _time, host, Image`                                                                                                                                           | Shows only the selected fields (`_time`, `host`, `Image`) in a tabular view.                                                                                                                                                                                                           |
| **rename**                        | Renames fields for readability.                                                                                          | `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 \| rename Image as Process`                                                                                                                                            | Changes the field name `Image` → `Process` in results.                                                                                                                                                                                                                                 |
| **dedup**                         | Removes duplicate values for a field.                                                                                    | `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 \| dedup Image`                                                                                                                                                        | Only keeps the **first unique occurrence** of `Image`, removing duplicates.                                                                                                                                                                                                            |
| **sort**                          | Sorts results in ascending/descending order.                                                                             | `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 \| sort - _time`                                                                                                                                                       | Sorts events by `_time` in **descending order** (latest first). Use `+` or no sign for ascending.                                                                                                                                                                                      |
| **chart**                         | Creates statistical visualizations (charts).                                                                             | `index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 \| chart count by _time, Image`                                                                                                                                        | Produces a chart with **count of events** grouped by `_time` and `Image`.                                                                                                                                                                                                              |
| **eval**                          | Creates or modifies fields with expressions.                                                                             | `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 \| eval Process_Path=lower(Image)`                                                                                                                                     | Creates new field `Process_Path` by converting `Image` values to **lowercase**.                                                                                                                                                                                                        |
| **rex**                           | Extracts fields using regex patterns.                                                                                    | `index="main" EventCode=4662 \| rex max_match=0 "[^%](?<guid>{.*})" \| table guid`                                                                                                                                               | Extracts all GUID values matching the regex into a new field `guid`.                                                                                                                                                                                                                   |
| **lookup**                        | Enriches data with external CSV lookup files.                                                                            | `index="main" \| lookup malware_lookup.csv filename OUTPUT is_malware`                                                                                                                                                           | Matches `filename` in events with lookup file and adds `is_malware` column.                                                                                                                                                                                                            |
| **inputlookup**                   | Reads lookup files directly (without search).                                                                            | `\| inputlookup malware_lookup.csv`                                                                                                                                                                                              | Displays all rows in the lookup file `malware_lookup.csv`.                                                                                                                                                                                                                             |
| **Time Range Filtering**          | Restricts search by time (using earliest/latest).                                                                        | `index="main" earliest=-7d EventCode!=1`                                                                                                                                                                                         | Returns events from **last 7 days**, excluding `EventCode=1`.                                                                                                                                                                                                                          |
| **transaction**                   | Groups related events into a single "transaction".                                                                       | `index="main" sourcetype="WinEventLog:Sysmon" (EventCode=1 OR EventCode=3) \| transaction`                                                                                                                                       | Groups together related EventCode 1 & 3 logs into a **session-like transaction**.                                                                                                                                                                                                      |
| **Subsearches**                   | Nested searches used inside brackets `[ ]`.                                                                              | `index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 NOT [ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 \| top limit=100 Image \| fields Image ] \| table _time, Image, CommandLine, User, ComputerName` | Subsearch finds **top 100 Images** and excludes them from the main search. Then shows details of the remaining processes.                                                                                                                                                              |


**This CSV file should be added as a new Lookup table as follows.**


![](../attachments/Pasted%20image%2020250905111956.png)


![](../attachments/Pasted%20image%2020250905112040.png)

![](../attachments/Pasted%20image%2020250905112128.png)

![](../attachments/Pasted%20image%2020250905112209.png)


`important`
- [https://docs.splunk.com/Documentation/SCS/current/SearchReference/Introduction](https://docs.splunk.com/Documentation/SCS/current/SearchReference/Introduction)
- [https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/](https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchReference/)
- [https://docs.splunk.com/Documentation/SplunkCloud/latest/Search/](https://docs.splunk.com/Documentation/SplunkCloud/latest/Search/)

### How To Identify The Available Data


#### **1. eventcount**

- **Purpose:** Shows the number of events across all indexes.
    
- **Example SPL:**
    

`| eventcount summarize=false index=* | table index`

- **Explanation:** Counts events for each index individually. `summarize=false` prevents aggregation across time or indexes. `table index` formats the output in a simple table, showing only index names and counts.
    

---

#### **2. metadata**

- **Purpose:** Retrieves metadata about sourcetypes or sources. Useful to identify available data sources and their characteristics.
    

##### a) Metadata for sourcetypes

- **Example SPL:**
    

`| metadata type=sourcetypes`

- **Explanation:** Lists all sourcetypes with information such as:
    
    - `firstTime`: When the sourcetype first appeared
        
    - `lastTime`: When it was last seen
        
    - `totalCount`: Number of events
        

##### b) Simplified metadata for sourcetypes

- **Example SPL:**
    

`| metadata type=sourcetypes index=* | table sourcetype`

- **Explanation:** Displays only the sourcetype names in a table. Useful for quickly identifying all data types in the environment.
    

##### c) Metadata for sources

- **Example SPL:**
    

`| metadata type=sources index=* | table source`

- **Explanation:** Shows all unique data sources ingested into Splunk, such as files, logs, or scripts.
    

---

#### **3. table**

- **Purpose:** Displays selected fields from events in tabular form.
    

##### a) Show raw event data

- **Example SPL:**
    

`sourcetype="WinEventLog:Security" | table _raw`

- **Explanation:** Shows the complete raw event data for the specified sourcetype. Useful to understand what the original log looks like.
    

##### b) Show all fields

- **Example SPL:**
    

`sourcetype="WinEventLog:Security" | table *`

- **Explanation:** Displays every field extracted from the events of a sourcetype. ⚠️ Can be very wide if many fields exist. Good for exploring available fields.
    

##### c) Show specific fields

- **Example SPL:**
    

`sourcetype="WinEventLog:Security" | fields Account_Name, EventCode | table Account_Name, EventCode`

- **Explanation:** Displays only the selected fields in a table. Makes analysis easier by focusing on relevant information.
    

---

#### **4. fieldsummary**

- **Purpose:** Summarizes all fields found in events and provides statistics.
    
- **Example SPL:**
    

`sourcetype="WinEventLog:Security" | fieldsummary`

- **Explanation:** Returns stats per field:
    
    - Count of events containing the field
        
    - Number of distinct values
        
    - Minimum, maximum, mean, standard deviation
        
    - Sample values
        
- Useful for discovering key fields or detecting anomalies.
    

---

#### **5. bucket + stats + sort**

- **Purpose:** Groups events by time and counts them, with sorting.
    
- **Example SPL:**
    

`index=* sourcetype=* | bucket _time span=1d | stats count BY _time, index, sourcetype | sort - _time`

- **Explanation:**
    
    - `bucket _time span=1d` groups events into 1-day intervals
        
    - `stats count BY _time, index, sourcetype` counts events for each combination
        
    - `sort - _time` sorts by latest day first
        
- Useful for trend analysis over time.
    

---

#### **6. rare**

- **Purpose:** Identifies uncommon or unusual events.
    

##### a) Rare indexes & sourcetypes

- **Example SPL:**
    

`index=* sourcetype=* | rare limit=10 index, sourcetype`

- **Explanation:** Lists the 10 least common combinations of index and sourcetype. Useful for spotting rare or abnormal event types.
    

##### b) Rare field values

- **Example SPL:**
    

`index="main" | rare limit=20 useother=f ParentImage`

- **Explanation:** Shows the 20 least common values of a specific field (`ParentImage`). Helps detect unusual parent processes.
    

##### c) Rare combinations of multiple fields

- **Example SPL:**
    

`index=* sourcetype=* | rare limit=10 field1, field2, field3`

- **Explanation:** Finds the 10 least common combinations of specified fields. Replace `field1, field2, field3` with fields of interest. Useful for anomaly detection across multiple attributes.
    

---

#### **7. fieldsummary + where**

- **Purpose:** Summarizes fields with filtering.
    
- **Example SPL:**
    

`index=* sourcetype=* | fieldsummary | where count < 100 | table field, count, distinct_count`

- **Explanation:** Filters the field summary to show only fields appearing in fewer than 100 events. Useful for detecting rare or unusual fields.
    

---

#### **8. sistats**

- **Purpose:** Summarizes events across multiple dimensions.
    
- **Example SPL:**
    

`index=* | sistats count BY index, sourcetype, source, host`

- **Explanation:** Aggregates event counts by index, sourcetype, source, and host. Helps visualize data diversity and distribution across the environment.

### Data and field identification approach 2: Leverage Splunk's User Interface


- Data sources
	- settings ->data inputs
	- we can list various data input methods including files and directories many more
- Data (Events)
	- search & reporting app
	- `fast mode` for quick scan through 
	- `verbose mode` dive deep into each events
	- `*` in the search bar will bring all the indexed data
	- can select the time range
- Fields
	- if we click on any event we can see the data in the left side all the available fields 
	- selected fields, interesting fields, all fields
- Data models
	-  provide an organized, hierarchical view of our data, simplifying complex datasets into understandable structures. They're designed to make it easier to create meaningful reports, visualizations, and dashboards without needing a deep understanding of the underlying data sources or the need to write complex SPL queries.
	- `accessing data models` settings --> Data Models (under the knowledge section)--> if we did not find anything then execute any query 
	- `understand existing data models` we see list of available data models . these might include models created by ourselves 
	- `Exploring Data Models`: By clicking on the name of a Data Model, we are taken to the `Data Model Editor`. This is where the true power of Data Models lies. Here, we can view the hierarchical structure of the data model, which is divided into `objects`. Each object represents a specific part of our data and contains `fields` that are relevant to that object.
![](../attachments/Pasted%20image%2020250905122707.png)

- `Pivots` that allows us to create complex reports and visualizations without writing SPL queries. They provide an interactive, drag-and-drop interface for defining and refining our data reporting criteria. As such, they're also a fantastic tool for identifying and exploring the available data and fields within our Splunk environment. To start with Pivots to identify available data and fields, we can use the `Pivot` button that appears when we're browsing a particular data model in the `Data Models` page.
![](../attachments/Pasted%20image%2020250905122828.png)

![](../attachments/Pasted%20image%2020250905122900.png)

### Questions

Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through an SPL search against all data the account name with the highest amount of Kerberos authentication ticket requests. Enter it as your answer.

```
index=* EventCode=4768
| stats count by Account_Name
```

Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through an SPL search against all 4624 events the count of distinct computers accessed by the account name SYSTEM. Enter it as your answer.

```
index=* EventCode=4624 Account_Name="SYSTEM"
| stats dc(ComputerName)
```


Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through an SPL search against all 4624 events the account name that made the most login attempts within a span of 10 minutes. Enter it as your answer.

```
index=* EventCode=4624
| stats min(_time) as first_time max(_time) as last_time count by Account_Name
| eval span = last_time - first_time
| eval logins_per_10min = (count / span) * 600
| sort - logins_per_10min
| head 1
```


---
---

## Using splunk applications


- apps, are packages that we add to our Splunk Enterprise or Splunk Cloud deployments to extend capabilities and manage specific types of operational data
- In this segment, we'll be leveraging the `Sysmon App for Splunk` developed by Mike Haag.
- pre-built dashboards, search capability and knowledge objects 

1. Sign up for a free account at [splunkbase](https://splunkbase.splunk.com/)
2. 1. Once registered, log into your account
3. Head over to the [Sysmon App for Splunk](https://splunkbase.splunk.com/app/3544) page to download the application.
4. Add the application 

![](../attachments/Pasted%20image%2020250905130816.png)

![](../attachments/Pasted%20image%2020250905130904.png)

upload the file 
5. Adjust the application's [macro](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Definesearchmacros) so that events are loaded as follows. (no need to specify every time )

![](../attachments/Pasted%20image%2020250905131053.png)

add new

![](../attachments/Pasted%20image%2020250905131143.png)

Let's access the Sysmon App for Splunk by locating it in the "Apps" column on the Splunk home page and head over to the `File Activity` tab.

![](../attachments/Pasted%20image%2020250905131240.png)

Let's now specify "All time" on the time picker and click "Submit". Results are generated successfully; however, no results are appearing in the "Top Systems" section.
We can fix that by clicking on "Edit" (upper right hand corner of the screen) and editing the search.

![](../attachments/Pasted%20image%2020250905131419.png)

The Sysmon Events with ID 11 do not contain a field named `Computer`, but they do include a field called `ComputerName`. Let's fix that and click "Apply"

![](../attachments/Pasted%20image%2020250905131509.png)
### questions
 Access the Sysmon App for Splunk and go to the "Reports" tab. Fix the search associated with the "Net - net view" report and provide the complete executed command as your answer. Answer format: net view /Domain:_.local
`net view /DOMAIN:uniwaldo.local`

Access the Sysmon App for Splunk, go to the "Network Activity" tab, and choose "Network Connections". Fix the search and provide the number of connections that SharpHound.exe has initiated as your answer.
`6`


---
---

## Intrusion detection with splunk (real world scenario)

`some data sets`
[BOTS](https://github.com/splunk/botsv3). Alternatively, [nginx_json_logs](https://raw.githubusercontent.com/elastic/examples/refs/heads/master/Common%20Data%20Formats/nginx_json_logs/nginx_json_logs) is a handy resource providing us with dummy logs in JSON format.


```shell
#see what are all the data available
index="main" earliest=0
```


**check what are all the data are available**

```shell
index=main | stats count by sourcetype
```


**look at sysmon logs**
```shell
index=main sourcetype="WinEventLog:Sysomon"
```

search for `uniwaldo.local`
```shell
index=main "uniwaldo.local"
index=main "*uniwaldo.local*"

#more efficient

index=main ComputerName="*uniwaldo.local*"
```


### Embracing The Mindset Of Analysts, Threat Hunters, & Detection Engineers

**listing the eventcode and its count in the dataset**

```shell
index=main sourcetype:"WinEventLog:Sysmon" | stats count by EventCode
```


**unusual parent-child trees**

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 
| stats count by ParentImage, Image

# check for cmd and powershell image 
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image=*cmd.exe* OR Image=*powershell.exe*)
| stats count by ParentImage, Image

```

**notepad was started cmd and powershell dive deeper** 

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image=*cmd.exe* OR Image=*powershell.exe*) ParentImage="C:\\Windows\\System32\\notepad.exe"
```

**so note pad is executed some command that is connecting 10.0.0.229 we need to check the source type **

```shell
index="main" 10.0.0.229 
|  stats count by sourcetype
```


**we can see linux is also communicated with the ip. we can see which ** 
```shell
index="main" 10.0.0.229 sourcetype="linux:syslog"
```

**we need to check in win. any command that has this IP**
```shell
index=main 10.0.0.229 sourcetype="WinEventLog:sysmon" | stats count by CommandLine, host
```

**it might be DCSync attack so to detect that we search 4662 and access was extended right 0x100 and user account not a system account**

```shell
index=main EventCode=4662 Access_Mask=0x100 Account_Name!=*$
```
we check the properties field to conform the attack 
object type 
{19195a5b-6da0-11d0-afd3-00c04fd930c9}

this obj was accessed 
this attack is used to replicate AD objects to dump password hashes from the domain controller

**next we look for lsass dumping**
```shell
index=main EventCode=10 lsass | stats count by SourceImage

#explore notepad
index="main" EventCode=10 lsass SourceImage="C:\\Windows\\System32\\notepad.exe"

```

### creating meaningful alerts

`create an alert to detect malware making API calls firm UNKNOWN memory regions (protential shellcod/ injection)`

**setp 1: find where UNKNOWN show up**
```shell
index="main" CallTrace="*UNKNOWN*" | stats count by EventCode
```


**step 2: group by process (sourceimage)**
```shell
index="main" CallTrace="*UNKNOWN*" | stats count by SourceImage
```

many false positivies like .NET JIT or electron apps

**step3: filter out obvious noise**
```shell
| where SourceImage!=TargetImage
```

exclude .NET JIT
```shell
... SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll*
```
exclude WOOW64 noise

```shell
... CallTrace!=*wow64*
```
exclude explorer
```shell
... SourceImage!="C:\\Windows\\Explorer.EXE"
```

**step4: refine** 
```shell
index="main" CallTrace="*UNKNOWN*" 
  SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* 
  SourceImage!="C:\\Windows\\Explorer.EXE" 
| where SourceImage!=TargetImage 
| stats count by SourceImage, TargetImage, CallTrace

```



---
---

## Intrusion Detection With Splunk Based On TTPs

- the first approach is playing a game of `spot the known`.
- The second approach, `while still informed by an understanding of attacker TTPs`, leans heavily on statistical analysis and anomaly detection to identify abnormal behavior within the sea of normal activity. This strategy is more of a game of `spot the unusual`.
- `the key is to understand our data and environment, then carefully tune our queries and thresholds to balance the need for accurate detection with the desire to avoid false positives`.

### Detection of Reconnaissance Activities leveraging native windows binaries 

attackers are using the built in tools to gather information from the internal tools
- **System info** → `systeminfo`, `hostname`, `tasklist`
- **User info** → `net user`, `whoami /all`, `net localgroup administrators`
- **Domain info** → `net group /domain`, `nltest /dclist`, `dsquery`
- **Network info** → `ipconfig /all`, `arp -a`, `netstat -ano`
- **Shares & services** → `net share`, `sc query`

example: `net.exe` → enumerate users, groups, shares

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 Image=*\\ipconfig.exe OR Image=*\\net.exe OR Image=*\\whoami.exe OR Image=*\\netstat.exe OR Image=*\\nbtstat.exe OR Image=*\\hostname.exe OR Image=*\\tasklist.exe | stats count by Image,CommandLine | sort - count
```

### Detection Of Requesting Malicious Payloads/Tools Hosted On Reputable/Whitelisted Domains (Such As githubusercontent.com)

It means watching for when attackers try to **download malware from trusted websites (like GitHub)** to avoid being blocked, and creating alerts for that activity.

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=22  QueryName="*github*" | stats count by Image, QueryName
```

### Detection Of PsExec Usage

- PsExec = **legit admin tool** from **Sysinternals suite**.
- Used by IT admins to run commands **remotely** on Windows machines.
- Needs **Local Administrator** rights.
`psexec \\target cmd.exe` will open remote shell on another machine

attackers use [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) which is a  [Windows Sysinternals](https://learn.microsoft.com/en-us/sysinternals/) tool which can be used for lateral movement once they compromised one system and want to spread . instead of malware they use PsExec 

Several MITRE ATT&CK techniques, including `T1569.002 (System Services: Service Execution)`, `T1021.002 (Remote Services: SMB/Windows Admin Shares)`, and `T1570 (Lateral Tool Transfer)`, have seen PsExec in play.

this is how the PsExec works

| **Step** | **Activity**                      | **What PsExec Actually Does**                                                                             | **Sysmon/Windows Events to Monitor**                                                                                                                                | **Detection/Notes**                                                                                             |
| -------- | --------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| **1**    | **Network logon**                 | PsExec authenticates to target via **SMB** using provided creds (admin required).                         | - **Windows 4624 (Logon)** → Type 3 (network)- **Windows 4625** (failed logon, if bad creds)                                                                        | Look for unusual admin logons from non-admin machines (e.g., user workstation logging in as domain admin).      |
| **2**    | **Copy `PSEXESVC.exe` to Admin$** | PsExec drops its service binary into the hidden admin share `\\Target\Admin$\PSEXESVC.exe`.               | - **Sysmon 11 (File Create)** → File path: `C:\Windows\PSEXESVC.exe`                                                                                                | This file is a strong PsExec indicator. Legit admin tools rarely drop executables into Admin$.                  |
| **3**    | **Service installed**             | PsExec registers a service **PSEXESVC** using Service Control Manager (SCM).                              | - **Sysmon 13 (Registry Set)** → Registry path: `HKLM\SYSTEM\CurrentControlSet\Services\PSEXESVC`- **Windows 7045 (Service Installed)** → Service name = `PSEXESVC` | Look for service creation events with suspicious names (`PSEXESVC`). Rare in normal environments.               |
| **4**    | **Named pipe communications**     | PsExec sets up a **named pipe** (`\PSEXESVC`) to communicate between attacker and target.                 | - **Sysmon 17 (Pipe Created)** → Pipe name: `\PSEXESVC`- **Sysmon 18 (Pipe Connected)** → Client connects to pipe                                                   | Named pipes are strong PsExec signatures. Look for unusual named pipes created by `services.exe`.               |
| **5**    | **Remote process execution**      | The service executes requested commands (e.g., `cmd.exe`, `ipconfig`, `powershell.exe`) under **SYSTEM**. | - **Sysmon 1 (Process Creation)** → Parent = `PSEXESVC.exe`, Child = attacker-specified process                                                                     | Look for processes spawned by `PSEXESVC.exe`. Example: SYSTEM → cmd.exe or powershell.exe with suspicious args. |
| **6**    | **Cleanup**                       | PsExec stops & deletes the service, removes `PSEXESVC.exe` (sometimes fails, leaving artifacts).          | - **Sysmon 11 (File Delete / Write)** if monitored- Registry remnants under `Services\PSEXESVC`                                                                     | Sometimes `PSEXESVC.exe` remains if cleanup fails. That’s a great forensic artifact.                            |

**Case 1: Leveraging Sysmon Event ID 13**

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath" | rex field=Details "(?<reg_file_name>[^\\\]+)$" | eval reg_file_name = lower(reg_file_name), file_name = if(isnull(file_name),reg_file_name,lower(file_name)) | stats values(Image) AS Image, values(Details) AS RegistryDetails, values(_time) AS EventTimes, count by file_name, ComputerName
```

Among the `less frequent` search results, it is evident that there are indications of execution resembling PsExec.

**Case 2: Leveraging Sysmon Event ID 11**

“Show me a summary of all files created or modified by the Windows `System` process, along with a count of how many times each file was created.”
```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image=System | stats count by TargetFilename
```

less frequent

**Case 3: Leveraging Sysmon Event ID 18**

this is used to make a C2

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=18 Image=System | stats count by PipeName
```

### Detection of utilizing archive files for transferring tools or data exfiltration

 `zip`, `rar`, or `7z` files for transferring tools to a compromised host or exfiltrating data from it

```shell
index="main" EventCode=11 (TargetFilename="*.zip" OR TargetFilename="*.rar" OR TargetFilename="*.7z") | stats count by ComputerName, User, TargetFilename | sort - count
```

### Detection Of Utilizing PowerShell or MS Edge For Downloading Payloads/Tools

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*powershell.exe*" |  stats count by Image, TargetFilename |  sort + count
```

The `*Zone.Identifier` is indicative of a file downloaded from the internet or another potentially untrustworthy source. Windows uses this zone identifier to track the security zones of a file. The `Zone.Identifier` is an ADS (Alternate Data Stream) that contains metadata about where the file was downloaded from and its security settings.

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=11 Image="*msedge.exe" TargetFilename=*"Zone.Identifier" |  stats count by TargetFilename |  sort + count
```

### Detection of execution form atypical or suspicious locations

programs that start (execute) from directories where normal trusted programs usually dont live

If you suddenly see an `.exe` or `.dll` running from places like:
- `C:\Users\<username>\AppData\Local\Temp\`
- `C:\Users\Public\`
- `C:\Windows\Temp\`
- Desktop or Downloads folders

```shell
index="main" EventCode=1 | regex Image="C:\\\\Users\\\\.*\\\\Downloads\\\\.*" |  stats count by Image
```

### Detection Of Executables or DLLs Being Created Outside The Windows Directory

```shell
index="main" EventCode=11 (TargetFilename="*.exe" OR TargetFilename="*.dll") TargetFilename!="*\\windows\\*" | stats count by User, TargetFilename | sort + count
```

### Detection Of Misspelling Legitimate Binaries

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (CommandLine="*psexe*.exe" NOT (CommandLine="*PSEXESVC.exe" OR CommandLine="*PsExec64.exe")) OR (ParentCommandLine="*psexe*.exe" NOT (ParentCommandLine="*PSEXESVC.exe" OR ParentCommandLine="*PsExec64.exe")) OR (ParentImage="*psexe*.exe" NOT (ParentImage="*PSEXESVC.exe" OR ParentImage="*PsExec64.exe")) OR (Image="*psexe*.exe" NOT (Image="*PSEXESVC.exe" OR Image="*PsExec64.exe")) |  table Image, CommandLine, ParentImage, ParentCommandLine
```

### Detection Of Using Non-standard Ports For Communications/Transfers

```shell
index="main" EventCode=3 NOT (DestinationPort=80 OR DestinationPort=443 OR DestinationPort=22 OR DestinationPort=21) | stats count by SourceIp, DestinationIp, DestinationPort | sort - count
```

### question

Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the password utilized during the PsExec activity. Enter it as your answer.

`index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 CommandLine="*psexec*"`

in that see CommandLine field 

---
---

## Detecting Attacker Behavior with splunk based on analytics

Instead of rules, watch for **unusual behavior** compared to what’s normal

`streamstats` is a Splunk command that calculates **running totals, averages, counts, or time differences** across events in a stream.

Instead of only hunting for specific bad tools, you can let Splunk watch for **weird spikes or changes in behavior**.  
For example, if `notepad.exe` suddenly opens 200 network connections, Splunk can flag that. This is done with statistical tools like `streamstats`.

### Example

- look at sysmon eventid 3 for network connecton
- group events into hourly buckets "like for every process count many network connections it made in each 1-hour window"
- for each process calculate a running avg and standard deviation of network connections over last 24 
- If a process makes significantly more network connections than usual (over average + half a standard deviation), mark it as an **outlier**.
- Show only suspicious activity

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3 | bin _time span=1h | stats count as NetworkConnections by _time, Image | streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image | eval isOutlier=if(NetworkConnections > (avg + (0.5*stdev)), 1, 0) | search isOutlier=1
```


### Detection Of Abnormally Long Commands

```shell
index="main" sourcetype="WinEventLog:Sysmon" Image=*cmd.exe | eval len=len(CommandLine) | table User, len, CommandLine | sort - len
```

```shell
index="main" sourcetype="WinEventLog:Sysmon" Image=*cmd.exe ParentImage!="*msiexec.exe" ParentImage!="*explorer.exe" | eval len=len(CommandLine) | table User, len, CommandLine | sort - len
```

### Detection of abnormal cmd.exe activity

uses bucket concept

```shell
index="main" EventCode=1 (CommandLine="*cmd.exe*") | bucket _time span=1h | stats count as cmdCount by _time User CommandLine | eventstats avg(cmdCount) as avg stdev(cmdCount) as stdev | eval isOutlier=if(cmdCount > avg+1.5*stdev, 1, 0) | search isOutlier=1
```

### Detection Of Processes Loading A High Number Of DLLs In A Specific Time

show me the image that is loading more then 3 distinct in one hour of time 

```shell
index="main" EventCode=7 | bucket _time span=1h | stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image | where unique_dlls_loaded > 3 | stats count by Image, unique_dlls_loaded
```

next they are using some patterns to filter out like bunch of paths that should ignore , then one hour group next count unique dll per process and the number of dll (threshold) then summarize it

```shell
index="main" EventCode=7 NOT (Image="C:\\Windows\\System32*") NOT (Image="C:\\Program Files (x86)*") NOT (Image="C:\\Program Files*") NOT (Image="C:\\ProgramData*") NOT (Image="C:\\Users\\waldo\\AppData*")| bucket _time span=1h | stats dc(ImageLoaded) as unique_dlls_loaded by _time, Image | where unique_dlls_loaded > 3 | stats count by Image, unique_dlls_loaded | sort - unique_dlls_loaded
```

### Detection Of Transactions Where The Same Process Has Been Created More Than Once On The Same Computer

Look at all processes on each computer. If the same process runs more than once, record it along with what started it, and count how often it happened. This can help identify suspicious repeated executions, which might indicate malware or scripts running in the background.

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | transaction ComputerName, Image | where mvcount(ProcessGuid) > 1 | stats count by Image, ParentImage
```

`rundll32.exe` and `svchost.exe` has some kind of more count

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1  | transaction ComputerName, Image  | where mvcount(ProcessGuid) > 1 | search Image="C:\\Windows\\System32\\rundll32.exe" ParentImage="C:\\Windows\\System32\\svchost.exe" | table CommandLine, ParentCommandLine
```

### question

Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through an analytics-driven SPL search against all data the source process images that are creating an unusually high number of threads in other processes. Enter the outlier process name as your answer where the number of injected threads is greater than two standard deviations above the average. Answer format: _.exe

```shell
index="main" sourcetype="WinEventLog:Sysmon" EventCode=8
| bin _time span=1h
| stats count as ThreadsInjected by SourceImage, TargetImage, _time
| stats avg(ThreadsInjected) as avgThreads stdev(ThreadsInjected) as sdThreads by SourceImage
```

---
---

## skill assessment

Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the process that created remote threads in rundll32.exe. Answer format: _.exe

```shell

index="main" sourcetype="WinEventLog:Sysmon" EventCode=8 TargetImage=*rundll32.exe
| stats count by SourceImage, TargetImage

```

Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the process that started the infection. Answer format: _.exe

rundll32.exe
