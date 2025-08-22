
---

## 🖥️ Linux System Information Commands – Cheat Sheet

|**Command**|**Description**|**Example Usage**|
|---|---|---|
|`whoami`|Displays current username.|`whoami`|
|`id`|Returns user identity (UID, GID, groups).|`id`|
|`hostname`|Sets or prints the system's hostname.|`hostname`|
|`uname`|Prints basic OS and hardware information.|`uname -a`|
|`pwd`|Prints the present working directory.|`pwd`|
|`ifconfig`|Views or configures network interfaces (older systems).|`ifconfig eth0`|
|`ip`|Shows/manages IP address and routes (modern replacement for ifconfig).|`ip addr show`|
|`netstat`|Displays network connections and routing tables. _(deprecated)_|`netstat -tuln`|
|`ss`|Displays socket statistics (faster replacement for `netstat`).|`ss -tuln`|
|`ps`|Shows the currently running processes.|`ps aux`|
|`who`|Shows who is logged in.|`who`|
|`env`|Prints environment variables.|`env`|
|`lsblk`|Lists block devices (hard disks, partitions, etc).|`lsblk`|
|`lsusb`|Lists USB devices connected to the system.|`lsusb`|
|`lsof`|Lists open files and associated processes.|`lsof -i :80`|
|`lspci`|Lists all PCI devices (like graphic cards, NICs, etc.).|`lspci`|
|`ssh user@ip`|Logs into another system remotely via SSH.|`ssh user@192.168.1.10`|

---
---

## 1. `ifconfig` (Interface Configuration)

### 📌 What it does:

`ifconfig` shows or configures a network interface (like your Ethernet or Wi-Fi adapter). It’s now deprecated in many modern systems in favor of `ip`, but still widely used in older or minimal Linux distros.

### ✅ Common usage:

```bash
ifconfig
```

### 🔍 Output explained:

- **eth0** / **wlan0**: Interface names (Ethernet or Wi-Fi)
    
- **inet**: The IPv4 address
    
- **inet6**: IPv6 address
    
- **RX / TX packets**: Received and transmitted data
    

### 🛠️ Use cases:

- Checking IP addresses
    
- Enabling/disabling interfaces (e.g., `ifconfig eth0 down`)
    

---

## 2. `ip` (IP Tool)

### 📌 What it does:

Replaces older tools like `ifconfig`, `route`, and `netstat`. It's more powerful and modern.

### ✅ Common usage:

```bash
ip a          # Show all interfaces and their IPs
ip r          # Show routing table
ip link       # Show network interfaces
```

### 🔍 Output explained:

- `lo`, `eth0`, `wlan0`: Network interfaces
    
- `inet`: IP address
    
- `state UP/DOWN`: Whether the interface is active
    

### 🛠️ Use cases:

- Checking IPs and interface status
    
- Configuring network interfaces
    
- Routing diagnostics
    

---

## 3. `ps` (Process Status)

### 📌 What it does:

Lists currently running processes.

### ✅ Common usage:

```bash
ps aux        # Show all processes with detailed info
ps -ef        # Similar to aux, but with different formatting
```

### 🔍 Output explained:

- **USER**: Who started the process
    
- **PID**: Process ID
    
- **%CPU / %MEM**: CPU and memory usage
    
- **COMMAND**: The command that started the process
    

### 🛠️ Use cases:

- Monitoring processes
    
- Checking if a service is running
    
- Debugging performance issues
    

---

## 4. `ss` (Socket Statistics)

### 📌 What it does:

Displays socket (network connection) information. Replaces `netstat` in many modern systems.

### ✅ Common usage:

```bash
ss -tuln      # List listening TCP/UDP ports
ss -s         # Summary of all connections
```

### 🔍 Output explained:

- **Netid**: Type of socket (tcp, udp, etc.)
    
- **Local Address:Port**: Where the service is listening
    
- **State**: Status of the connection (LISTEN, ESTABLISHED)
    

### 🛠️ Use cases:

- Check which ports are open
    
- Find which service is using a port
    
- Monitor live connections
    

---

## 5. `netstat` (Network Statistics)

> 🔴 Deprecated in many systems, replaced by `ss`.

### ✅ Common usage:

```bash
netstat -tuln
```

### 🔍 Output explained:

Similar to `ss`:

- **Proto**: Protocol (tcp/udp)
    
- **Local Address**: IP and port
    
- **State**: Connection status
    

### 🛠️ Use cases:

Same as `ss` — used for checking active connections, listening ports.

---

## 6. `lsblk` (List Block Devices)

### 📌 What it does:

Displays information about block devices (disks, USBs, partitions).

### ✅ Common usage:

```bash
lsblk
```

### 🔍 Output explained:

- **NAME**: Device name (`sda`, `sda1`, `sdb`)
    
- **SIZE**: Disk size
    
- **TYPE**: `disk`, `part` (partition)
    
- **MOUNTPOINT**: Where it's mounted (like `/`, `/home`, `/mnt/usb`)
    

### 🛠️ Use cases:

- Viewing disk layout
    
- Checking USB drive or external disk
    
- Finding mount points
    

---

## Summary Table:

|Command|Purpose|Key Option|Modern?|
|---|---|---|---|
|`ifconfig`|Show network interfaces|`ifconfig`|❌ (deprecated)|
|`ip`|Configure/view network|`ip a`, `ip r`|✅|
|`ps`|Show running processes|`ps aux`|✅|
|`ss`|Show socket stats|`ss -tuln`|✅|
|`netstat`|Show network stats|`netstat -tuln`|❌ (deprecated)|
|`lsblk`|Show block storage devices|`lsblk`|✅|

---


