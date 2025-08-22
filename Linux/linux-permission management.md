## 🔐 Permission Management in Linux

Understanding and managing file permissions is crucial for system administration and security.

---

### **1. Permission Representation**

```bash
cry0l1t3@htb[/htb]$ ls -l /etc/passwd
-rwxrw-r-- 1 root root 1641 May  4 23:42 /etc/passwd
```

|Field|Description|
|---|---|
|`-`|File type (`-` = regular file, `d` = directory, `l` = symbolic link, etc.)|
|`rwx`|Owner's permissions: read (r), write (w), execute (x)|
|`rw-`|Group's permissions|
|`r--`|Others' permissions|
|`1`|Number of hard links|
|`root`|Owner of the file|
|`root`|Group owner of the file|
|`1641`|File size in bytes|
|`May 4 23:42`|Last modification date/time|
|`/etc/passwd`|File name|

---

### **2. Changing Permissions with `chmod`**

**Symbolic notation:**

```bash
chmod u+x script.sh     # Add execute to user
chmod g-w file.txt      # Remove write from group
chmod o=r file.txt      # Set read-only for others
```

**Octal notation (Binary → Octal):**

|Binary|Octal|Permission|
|---|---|---|
|111|7|rwx|
|101|5|r-x|
|100|4|r--|

```bash
chmod 754 file.sh  # rwxr-xr--
```

---

### **3. Changing Owner and Group**

**Change owner:**

```bash
chown newuser file.txt
```

**Change group:**

```bash
chgrp newgroup file.txt
```

**Change both:**

```bash
chown newuser:newgroup file.txt
```

---

### **4. Special Permissions**

#### 🛡 SUID (Set User ID)

- Executes the file with the permissions of the file **owner**.
    

```bash
chmod u+s script.sh
```

- Appears as: `-rwsr-xr-x`
    

#### 🛡 SGID (Set Group ID)

- Executes with the permissions of the file **group**.
    
- On directories: new files inherit group.
    

```bash
chmod g+s dir/
```

- Appears as: `drwxr-sr-x`
    

#### 🗂 Sticky Bit

- Applied on directories: only the file owner can delete or rename their files.
    

```bash
chmod +t /shared/folder
```

- Appears as: `drwxrwxrwt`
    

---

### 🧪 Examples

```bash
chmod 700 private.txt         # Owner can read/write/execute
chmod 644 public.txt          # Owner can rw, others can read
chmod 755 script.sh           # Owner can rwx, others rx
chown john:staff report.txt   # Change owner and group
chmod u+s /usr/bin/passwd     # Set SUID
chmod g+s /var/projects       # Set SGID
chmod +t /tmp                 # Set Sticky Bit
```

