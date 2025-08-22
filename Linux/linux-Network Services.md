Here's your **clean, complete, and structured revision note** on **Network Services in Linux**, covering SSH, NFS, Web Server, and VPN.

---

# 🌐 **Linux Notes – Network Services**

---

## 🔐 SSH (Secure Shell)

### 📦 Install OpenSSH

```bash
sudo apt update
sudo apt install openssh-server -y
```

### 📊 Check SSH Server Status

```bash
sudo systemctl status ssh
```

### 🔑 SSH Login

```bash
ssh username@hostname_or_ip
# Example:
ssh cry0l1t3@10.129.12.17
```

---

## 📁 NFS (Network File System)

### 📦 Install NFS Server & Client

```bash
# On the server:
sudo apt install nfs-kernel-server -y

# On the client:
sudo apt install nfs-common -y
```

### 📌 NFS Share Permissions

|Option|Description|
|---|---|
|`rw`|Read/Write access|
|`ro`|Read-only access|
|`no_root_squash`|Root user on client keeps root permissions|
|`root_squash`|Root on client is mapped to normal user|
|`sync`|Changes are committed to disk before transfer|
|`async`|Faster, but data may be lost if crash occurs|

---

### 🛠️ Create and Export NFS Share

1. **Create directory to share**
    

```bash
mkdir ~/nfs_sharing
```

2. **Edit `/etc/exports`**
    

```bash
echo '/home/cry0l1t3/nfs_sharing hostname(rw,sync,no_root_squash)' | sudo tee -a /etc/exports
```

3. **Verify exports**
    

```bash
cat /etc/exports | grep -v "#"
```

4. **Export shared directories**
    

```bash
sudo exportfs -a
```

---

### 📥 Mount NFS Share on Client

1. **Create mount point**
    

```bash
mkdir ~/target_nfs
```

2. **Mount remote share**
    

```bash
mount 10.129.12.17:/home/john/dev_scripts ~/target_nfs
```

3. **Check contents**
    

```bash
tree ~/target_nfs
```

---

## 🌍 Web Server

### 📦 Install Apache2

```bash
sudo apt install apache2 -y
```

### ⚙️ Basic Configuration (`/etc/apache2/apache2.conf` or VirtualHost file)

```apache
<Directory /var/www/html>
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>
```

---

### 🐍 Start Simple Python Web Server

**In current directory (default port 8000):**

```bash
python3 -m http.server
```

**With custom directory and port:**

```bash
python3 -m http.server 443 --directory /home/cry0l1t3/target_files
```

---

## 🔐 VPN (OpenVPN)

### 📦 Install OpenVPN

```bash
sudo apt install openvpn -y
```

### 🔌 Connect to VPN

```bash
sudo openvpn --config <file.ovpn>
# Replace with your .ovpn config file
```

---

## ✅ Quick Summary Table

|Service|Install|Start/Status|Notes|
|---|---|---|---|
|**SSH**|`apt install openssh-server`|`systemctl start/status ssh`|Secure shell access|
|**NFS**|`apt install nfs-kernel-server`|`exportfs -a`, `mount`|File sharing|
|**Apache**|`apt install apache2`|`systemctl status apache2`|Web server|
|**Python HTTP**|`python3 -m http.server`|N/A|Quick local server|
|**VPN**|`apt install openvpn`|`openvpn --config <file>`|Encrypted tunnel|

---

Would you like me to merge this with your previous Linux notes for a single complete revision document (PDF or Markdown format)?