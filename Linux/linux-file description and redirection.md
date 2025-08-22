
---

## 🧠 **Linux I/O Streams & Redirection – Cheat Sheet**

### 🔢 File Descriptors

|**Stream**|**Descriptor**|**Name**|**Used For**|
|---|---|---|---|
|STDIN|0|Standard Input|Input taken from user/keyboard or file|
|STDOUT|1|Standard Output|Normal output messages|
|STDERR|2|Standard Error|Error messages|

---

## 🔄 Redirection

### 📘 Basic Redirection

|**Syntax**|**Meaning**|
|---|---|
|`>`|Redirect STDOUT (overwrite file)|
|`>>`|Redirect STDOUT (append to file)|
|`2>`|Redirect STDERR|
|`2>>`|Redirect STDERR (append)|
|`&>`|Redirect both STDOUT and STDERR|
|`<`|Redirect STDIN (input from a file)|
|`<< EOF`|Here Document (multi-line input to a file)|

---

### 🔍 Examples from Your Commands

|**Command**|**Description**|
|---|---|
|`find /etc/ -name shadow`|Tries to find the file named `shadow` under `/etc`. May produce an error.|
|`find /etc/ -name shadow 2>/dev/null`|Hides any error messages (like permission denied).|
|`find /etc/ -name shadow 2>/dev/null > results.txt`|Redirects errors to null and STDOUT to `results.txt`.|
|`find /etc/ -name shadow 2> stderr.txt 1> stdout.txt`|Separately redirects STDERR to `stderr.txt` and STDOUT to `stdout.txt`.|
|`cat < stdout.txt`|Reads content of `stdout.txt` via STDIN (same as `cat stdout.txt`).|
|`find /etc/ -name passwd >> stdout.txt 2>/dev/null`|Appends output to `stdout.txt`, suppresses errors.|
|||

```bash
cat << EOF > stream.txt
```

| Starts a "Here Document", allows multi-line input to be written to `stream.txt`. You'd follow it with content and `EOF` to close. |

---

### 🧪 Pipe (`|`) – Send output of one command as input to another

|**Example**|**Explanation**|
|---|---|
|`find /etc/ -name *.conf 2>/dev/null \| grep systemd`|Find `.conf` files and filter for `systemd` related files.|
|`find /etc/ -name *.conf 2>/dev/null \| grep systemd \| wc -l`|Count how many systemd-related `.conf` files are found.|

---

## 📝 Summary Table

|**Command**|**Effect**|
|---|---|
|`>`|Redirect STDOUT to file (overwrite)|
|`>>`|Redirect STDOUT to file (append)|
|`2>`|Redirect STDERR to file|
|`&>`|Redirect both STDOUT and STDERR|
|`<`|Take input from file|
|`|`|
|`<< EOF`|Multi-line input redirection (Here Document)|

---

