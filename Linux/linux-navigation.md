
---

## 📁 Linux Navigation Commands – Cheat Sheet

|**Command**|**Description**|**Example Usage**|
|---|---|---|
|`pwd`|Prints the present working directory.|`pwd`|
|`ls`|Lists files and directories in the current path.|`ls`|
|`ls -l`|Lists in long format with permissions, owners, size, and timestamp.|`ls -l`|
|`ls -a`|Lists all files including hidden ones (starting with `.`).|`ls -a`|
|`ls -la`|Combines long listing and hidden files.|`ls -la`|
|`cd`|Changes the current working directory.|`cd /home/user/Desktop`|
|`cd ..`|Goes up one directory level.|`cd ..`|
|`cd ~`|Moves to the home directory.|`cd ~`|

---

### 📑 Breakdown of `ls -l` Output

```bash
drwxr-xr-x  2  cry0l1t3  htbacademy  4096  Nov 13 17:37  Desktop
```

|**Column**|**Description**|
|---|---|
|`drwxr-xr-x`|File type & permissions (`d` = directory, `rwx` = read/write/execute)|
|`2`|Number of hard links to the file/directory|
|`cry0l1t3`|Owner (user) of the file/directory|
|`htbacademy`|Group owner of the file/directory|
|`4096`|Size in bytes (or blocks for a directory)|
|`Nov 13 17:37`|Last modification date and time|
|`Desktop`|Name of the directory or file|

---
