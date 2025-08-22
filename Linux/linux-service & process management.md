
---

# 🧠 Linux Notes – **Service & Process Management**

---

## 🛠️ 1. **What Are Services and Processes?**

- **Process**: A running instance of a program.
    
- **Service (Daemon)**: A background process that usually starts at boot and runs continuously (like `ssh`, `nginx`, etc.).
    

---

## 🧰 2. **Managing Services with `systemctl` (Systemd)**

|Command|Description|
|---|---|
|`systemctl start <service>`|Start a service|
|`systemctl stop <service>`|Stop a service|
|`systemctl restart <service>`|Restart a service|
|`systemctl status <service>`|Check the status|
|`systemctl enable <service>`|Enable service at boot|
|`systemctl disable <service>`|Disable service at boot|
|`systemctl list-units --type=service`|List active services|
|`journalctl -u <service>`|Show service logs|

### 🔧 Example with `ssh`:

```bash
systemctl start ssh                     # Start SSH service
systemctl status ssh                   # Check SSH status
systemctl enable ssh                   # Enable SSH on boot
journalctl -u ssh.service --no-pager   # View SSH logs
```

---

## 🔍 3. **Viewing and Finding Processes**

|Command|Description|
|---|---|
|`ps -aux`|List all running processes|
|`ps -aux|grep ssh`|
|`top` / `htop`|Real-time process monitoring|
|`jobs`|List background jobs in the shell|

---

## ☠️ 4. **Killing a Process**

Every process has a **PID (Process ID)**, which is required to terminate it.

### ✋ Signals for Kill

|Signal|Description|
|---|---|
|`1`|**SIGHUP** – Terminal closed|
|`2`|**SIGINT** – Interrupt (Ctrl + C)|
|`3`|**SIGQUIT** – Quit (Ctrl + D)|
|`9`|**SIGKILL** – Kill forcefully (no cleanup)|
|`15`|**SIGTERM** – Request termination (default)|
|`19`|**SIGSTOP** – Stop (can’t be handled)|
|`20`|**SIGTSTP** – Suspend (Ctrl + Z)|

### 🔨 Kill Examples:

```bash
kill -9 <PID>           # Force kill
kill -15 <PID>          # Graceful terminate
kill -l                 # List all signals
```

---

## 🧫 5. **Process States**

|State|Meaning|
|---|---|
|**Running**|Actively executing|
|**Waiting**|Idle, waiting for resource|
|**Stopped**|Suspended by signal|
|**Zombie**|Process ended, still in process table|

---

## 🔙 6. **Background & Foreground Jobs**

### 🎯 Backgrounding a Process

```bash
ping -c 10 www.hackthebox.eu &   # Run in background
jobs                             # List background jobs
bg                               # Resume last job in background
```

### 🎯 Foregrounding a Process

```bash
fg 1     # Bring job 1 to foreground
```

---

## 🔄 7. **Execute Multiple Commands**

|Operator|Use|
|---|---|
|`;`|Run commands sequentially, regardless of success|
|`&&`|Run next only if previous command succeeds|
|`|`|

### 🔧 Examples:

```bash
echo "Start"; ls; echo "Done"            # Run all
mkdir test && cd test                    # Only if mkdir succeeds
cat file.txt | grep "admin"              # Pipe output
```

---

## 📝 8. **Quick Revision Table**

|Action|Command|
|---|---|
|Start/Stop/Restart|`systemctl start/stop/restart <service>`|
|Enable/Disable on Boot|`systemctl enable/disable <service>`|
|Status of a Service|`systemctl status <service>`|
|View logs|`journalctl -u <service>`|
|List all services|`systemctl list-units --type=service`|
|Search process|`ps -aux|
|Kill process|`kill -9 <PID>`|
|Background/Foreground|`jobs`, `bg`, `fg`|
|Combine Commands|`;`, `&&`, `|

---

Do you want me to combine these with your earlier **User Management** and **Package Management** notes into one full revision file or keep them in separate sections?