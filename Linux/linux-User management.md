
---

# 📘 Linux Notes – **User Management & Privilege Execution**

---

## 🧑‍💻 1. **User Management**

Linux is a multi-user operating system. Each user can have different roles, permissions, and settings. Managing users efficiently is essential for security and system administration.

### 📌 Key Concepts:

- Every user is identified by:
    
    - **Username**
        
    - **User ID (UID)**
        
    - **Group ID (GID)**
        
    - **Home Directory**
        
    - **Login Shell**
        

---

## 🧑‍🔧 2. **Execution as a User vs Root**

### 👤 **Execution as a User:**

- A normal user has limited access.
    
- Cannot install software or access other users' files without permission.
    
- Typically used for daily tasks.
    

### 👑 **Execution as Root (Superuser):**

- Has complete control over the system.
    
- Can modify system files, install/uninstall software, and manage users.
    
- Dangerous if misused – always use root privileges **only when required**.
    

---

## 🔐 3. **Important Commands for User Privileges**

|Command|Description|
|---|---|
|`sudo`|Execute a command as another user (default is root). Example: `sudo apt update`|
|`su`|Switch to another user. If no user is mentioned, defaults to root. Example: `su` or `su username`|

> ⚠️ Note: `sudo` is preferred over `su` for better auditing and limited privilege escalation.

---

## 👥 4. **User and Group Management Commands**

|Command|Description|Example|
|---|---|---|
|`useradd`|Creates a new user.|`sudo useradd john`|
|`userdel`|Deletes a user account and related files (with `-r`).|`sudo userdel -r john`|
|`usermod`|Modifies an existing user. Used to change username, shell, home directory, etc.|`sudo usermod -l newname oldname`|
|`passwd`|Changes the password of a user.|`passwd john`|
|`addgroup`|Adds a new group to the system.|`sudo addgroup developers`|
|`delgroup`|Deletes an existing group.|`sudo delgroup developers`|

---

## 📝 5. **Additional Useful Info (Important for Revision)**

### 📂 Home Directory:

- Created by default at `/home/username` unless specified.
    
- Can be manually created using:
    
    ```bash
    sudo useradd -m username
    ```
    

### 🛠 Default Shell:

- Bash is the default shell.
    
- You can set shell during user creation:
    
    ```bash
    sudo useradd -s /bin/bash username
    ```
    

### 🧾 User Info File:

- **`/etc/passwd`** – Stores user account details.
    
- **`/etc/shadow`** – Stores encrypted passwords.
    
- **`/etc/group`** – Lists group information.
    

### 🔒 Best Practices:

- Avoid logging in directly as root.
    
- Use `sudo` for specific admin tasks.
    
- Disable unused or suspicious users.
    

---

## 🧠 Summary for Quick Revision

|Topic|Summary|
|---|---|
|Execution as User|Limited permissions, safer.|
|Execution as Root|Full access, use with caution.|
|`sudo` vs `su`|`sudo` = run one command as root; `su` = full root shell.|
|User Management|Use `useradd`, `usermod`, `userdel`.|
|Group Management|Use `addgroup`, `delgroup`.|
|Change Password|`passwd username`|
|Important Files|`/etc/passwd`, `/etc/shadow`, `/etc/group`|

---
