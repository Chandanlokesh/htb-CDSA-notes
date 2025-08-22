
---

## 🔍 Finding Files and Directories – Cheat Sheet

### 📌 1. `which` – Locate Executable

|**Command**|**Description**|**Example**|
|---|---|---|
|`which <command>`|Shows the full path of the command's executable|`which python3`|

---

### 📌 2. `find` – Powerful File Search

|**Command**|**Description**|
|---|---|
|`find`|Base command for file search|
|`-type f`|Search for files only (`f = file`, `d = directory`)|
|`-name "*.conf"`|Search files with `.conf` extension|
|`-user root`|Search files owned by the user `root`|
|`-size +20k`|Files larger than 20 KiB (`+20M` for MB, `-20k` for less than 20KB)|
|`-newermt 2020-03-03`|Files modified after March 3, 2020|
|`-exec <command> {} \;`|Execute command on each result (e.g., `ls -al`)|
|`2>/dev/null`|Suppress errors by redirecting STDERR to `/dev/null`|

### ✅ **Example – Find and List All .conf Files Owned by Root Larger than 20KB**

```bash
find / -type f -name "*.conf" -user root -size +20k -exec ls -al {} \; 2>/dev/null
```

---

### 📌 3. `locate` – Fast File Lookup (uses pre-built database)

|**Command**|**Description**|
|---|---|
|`locate <filename>`|Instantly finds the path of a file|
|`locate *.conf`|Find all `.conf` files|
|`locate passwd`|Find files with the name “passwd”|
|`locate -i <name>`|Case-insensitive search|
|`locate -c <name>`|Count of matches|
|`updatedb`|Update the file database used by `locate`|

### ✅ **Example – Find All Case-Insensitive Matches for config**

```bash
locate -i config
```

---

