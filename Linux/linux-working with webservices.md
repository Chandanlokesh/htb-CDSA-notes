Here's a **structured revision note** for **Working with Web Services in Linux**, including Apache and Python web server usage.

---

# 🌐 **Linux Notes – Working with Web Services**

---

## 🧾 Apache Web Server (HTTP)

### 📦 Install Apache2

```bash
sudo apt update
sudo apt install apache2 -y
```

### ▶️ Start Apache Service

```bash
sudo systemctl start apache2
```

### 📁 Configuration File

```bash
/etc/apache2/ports.conf
```

> Used to configure which ports Apache listens on (e.g., 80, 8080).

---

### 🌐 Access Web Server

- Open in browser:  
    `http://localhost` or `http://localhost:8080` (if port changed)
    

---

## 🔧 Basic Web Service Commands

### 🧪 Test with `curl`

```bash
curl -I http://localhost:8080
# Fetch only HTTP headers

curl http://localhost
# Fetch entire HTML content
```

### 🧲 Download with `wget`

```bash
wget http://localhost
# Saves index.html to current directory
```

---

## 🐍 Python Simple HTTP Server

**Start server in current directory (default port 8000):**

```bash
python3 -m http.server
```

**Custom port:**

```bash
python3 -m http.server 8080
```

**Custom directory:**

```bash
python3 -m http.server 8080 --directory /home/user/myfiles
```

---

## ✅ Quick Summary Table

|Command|Description|
|---|---|
|`sudo apt install apache2 -y`|Installs Apache web server|
|`sudo systemctl start apache2`|Starts Apache|
|`/etc/apache2/ports.conf`|Apache port configuration|
|`curl -I http://localhost`|Shows response headers|
|`curl http://localhost`|Shows full web page content|
|`wget http://localhost`|Downloads index.html|
|`python3 -m http.server`|Starts a simple Python HTTP server|

---

Would you like to generate a combined PDF or editable doc of all Linux service management and web server notes?