
![](../attachments/Pasted%20image%2020250909101514.png)


NTA (network traffic analysis)= _looking at the "conversations" happening inside a network_.
**Every attacker must talk to your network.** No matter how stealthy they are, they need to send or receive data. That’s why analyzing traffic helps us detect threats.

### BPF Syntax (Berkeley Packet Filter)

This is like **Google search for packets**.  
You filter packets with conditions so you don’t drown in noise.
Examples:
- `tcp port 80` → only HTTP traffic.
- `host 192.168.1.5` → only packets from/to a specific host.
- `src net 10.0.0.0/24` → only packets from subnet 10.0.0.x.
- `udp and port 53` → DNS queries.

### The NTA Workflow

![](../attachments/Pasted%20image%2020250908201528.png)
- **Ingest Traffic** → capture with tcpdump, Wireshark, tap, etc.
- **Reduce Noise** → filter out unnecessary broadcast/multicast.
- **Analyze & Explore** → look for anomalies:
    - Plaintext traffic where encryption is expected.
    - Odd host-to-host communication.
    - Abnormal packet flags (e.g., too many SYNs).
- **Detect & Alert** → decide if it’s malicious or benign. IDS/IPS can help here.
- **Fix & Monitor** → patch or block → keep watching to confirm it’s solved.

---
---

## Networking Primer Layers 1-4


### OSI / TCP-IP Models

![](../attachments/Pasted%20image%2020250909101819.png)

### PDU
- Protocol Data Units
- A PDU is a data packet made up of control information and data encapsulated from each layer of the OSI model.

![](../attachments/Pasted%20image%2020250909102234.png)

- encapsulation in mind. As our data moves down the protocol stack, each layer will wrap the previous layers' data in a new bubble we call encapsulation. This bubble adds the necessary information of that layer into the header of the PDU.

![](../attachments/Pasted%20image%2020250909102516.png)

### MAC addressing

- MAC : media access control address
- It’s a **unique hardware identifier** burned into a network interface card (NIC).
- **Length**: 48 bits = 6 octets = 12 hexadecimal characters.

**`3C:52:82:5A:4B:11`**
- **First 3 octets (3C:52:82)** → **OUI (Organizationally Unique Identifier)** = who made the device (e.g., Intel, Cisco, etc.).
- **Last 3 octets (5A:4B:11)** → **Device Identifier** = unique ID for that NIC.
💡 That means no two NICs should have the same MAC address globally.

- MAC addresses operate at the **Data Link Layer (Layer 2)**.
- Used **inside a local network** (LAN, Wi-Fi).

👉 If you want to send data to another computer on the same LAN
- You use **IP address to know _who_ you want to reach.**
- Then your system asks: _“What’s the MAC address of that IP?”_
- That’s resolved using **ARP (Address Resolution Protocol)**.

![](../attachments/Pasted%20image%2020250909104749.png)

red - MAC
blue
green - IPv4

---
### IPv4 (internet protocol address)

- IP = internet protocol address
- Deliver data **from one host to another across networks**.
- Found at **OSI Layer 3 (Network Layer)**.
- Acts like a **postal address** → tells the world _where_ to deliver data.

**features**
- ip just sends packets doesnt guarantee delivery
- no error correction, no acknowledgement retails on higher protocols 

- **Length**: 32 bits → split into 4 octets (8 bits each).
- **Format**: Decimal, dotted notation. Example:
    - `192.168.86.243`
    - Each octet = 0–255.
👉 Why 0–255? Because 1 octet = 8 bits → max value = 11111111 (binary) = 255 (decimal).
Current standard (≈ 4.3 billion addresses total).

---

### IPv6

- **IPv4 exhaustion**: 4.3 billion addresses seemed huge in the 80s, but with phones, laptops, IoT devices → we ran out.
- Attempts to stretch IPv4 life:
    
    - **NAT (Network Address Translation)**
        
    - **CIDR (Classless Inter-Domain Routing)**
        
    - **VLSM (Variable Length Subnet Masking)**

Still not enough → **IPv6 was born**.

- **Length**: 128 bits = **16 octets**
- **Representation**: Hexadecimal, written in 8 groups of 4 hex digits.  
    Example:
    `2001:0db8:85a3:0000:0000:8a2e:0370:7334`
- **Shortened notation**:
    - Remove leading zeros → `2001:db8:85a3::8a2e:370:7334`

👉 Practically: IPv6 = **3.4 × 10³⁸ possible addresses** (almost infinite).  
Every grain of sand on Earth could have its own IP… several times over 🌍.


1. **Huge Address Space**
    - No need for NAT; every device can have a **global unique address**.
2. **Better Multicast Support**
    - Efficiently send data to many hosts at once (e.g., streaming).
3. **Anycast**
    - Same address assigned to multiple servers, but **nearest one replies**.
    - Useful for **load balancing & CDNs** (e.g., Cloudflare, Google DNS).
4. **Integrated Security**
    - IPSec is built into IPv6 standard (in IPv4, it was optional).
5. **Simplified Headers**
    - Easier for routers to process packets quickly.
#### 🔹 IPv6 Address Types

|**Type**|**Meaning**|**Analogy**|
|---|---|---|
|**Unicast**|One-to-one (single device).|Mailing a letter to your friend.|
|**Anycast**|One-to-nearest (group of devices, closest responds).|Calling a pizza chain’s **toll-free number** → you get the nearest branch.|
|**Multicast**|One-to-many (all in the group get it).|Sending a group WhatsApp message.|
|**Broadcast**|❌ Doesn’t exist in IPv6 (replaced by multicast).|N/A — no “shouting to everyone” anymore.|

### Transport Layer

- **Role**: Ensures end-to-end delivery of data between applications.
- **Protocols**: TCP (reliable, connection-oriented), UDP (fast, connectionless).
- **Encapsulation**: Breaks data into segments, adds ports, passes to IP layer.
- **Reassembly**: Reorders segments at destination.

### TCP vs UDP

|**Characteristic**|**TCP**|**UDP**|
|---|---|---|
|Transmission|Connection-oriented|Connectionless (fire-and-forget)|
|Connection Setup|3-way handshake|None|
|Data Delivery|Reliable (sequence + ACKs)|Unreliable (no checks)|
|Speed|Slower (overhead)|Faster (minimal overhead)|
|Best for|SSH, HTTP/S, FTP, Email|DNS, Video/Voice streaming, Gaming|
#### TCP Details
- **Reliable stream**: Tracks sequence numbers + ACKs.
- **Error handling**: Retransmits lost packets.
- **Example**: SSH → safe, complete commands.
- **Handshake (3-way)**:
    - Client → SYN
    - Server → SYN + ACK
    - Client → ACK 
        → Session established.
- **Teardown (graceful close)**:
    - FIN, ACK
    - FIN, ACK
    - ACK  
        → Session terminated.

#### UDP Details

- **Unreliable, fast** → no ACK, no reordering.
- **Best when loss is tolerable** (speed > reliability).
- **Examples**: DNS queries, video streaming, online gaming.

#### TCP Three-way Handshake

![](../attachments/Pasted%20image%2020250909130123.png)
#### TCP Session Teardown
![](../attachments/Pasted%20image%2020250909130204.png)

---
---

## OSI Layers 5–7 (Application Layer Protocols)

### HTTP
- hypertext transfer protocol
- default -> TCP 80 or 8000
- Transfers webpages, images, videos, etc. between client (browser) and server.

#### HTTP Methods Tables

|**Method**|**Detailed Description**|**Example**|
|---|---|---|
|**HEAD**|Same as GET but only retrieves headers (no body). Used to check if a resource exists or get metadata (size, last modified, etc.).|`HEAD /index.html` → Check if the file exists without downloading it.|
|**GET**|Requests a representation of a resource. Most common method. Safe and idempotent (does not change server data).|`GET /products.html` → Fetches product listing page.|
|**POST**|Submits data to the server to create a new resource or perform an action. Not idempotent (repeating creates duplicates).|`POST /login` with body `{ "user": "Alice", "pass": "123" }` → Log into account.|
|**PUT**|Creates or replaces a resource at the specified URI. Idempotent (repeating gives the same result).|`PUT /users/42` with `{ "name": "Alice" }` → Creates/updates user #42.|
|**DELETE**|Removes the resource at the specified URI. Idempotent (repeat = no effect if already deleted).|`DELETE /users/42` → Deletes user with ID 42.|
|**TRACE**|Echoes back the received request. Used for testing/debugging (rarely enabled due to security risks).|`TRACE /example` → Server returns same request headers.|
|**OPTIONS**|Returns supported HTTP methods for a resource. Helps clients know what actions are allowed.|`OPTIONS /api/users` → Response: `Allow: GET, POST, PUT, DELETE`.|
|**CONNECT**|Converts the request connection into a TCP/IP tunnel. Commonly used to enable HTTPS through proxies.|`CONNECT www.bank.com:443` → Proxy opens a secure tunnel for HTTPS traffic.|

### HTTPS
- HTTP secure
- default -> TCP 443 or 8443
- Encrypts communication (web browsing, banking, login).

#### TLS handshake
TLS (Transport Layer Security) handshake is the **process of two computers (client & server) agreeing on how to securely communicate** before sending actual data.

|#|Communication Between|Description|Analogy|
|---|---|---|---|
|1|**Client → Server**|**ClientHello**: Client proposes supported TLS version, cipher suites (encryption methods), and sends a random value.|You walk into a shop and say: _“I can talk in English or Spanish, which one do you prefer? Here’s a random phrase so our secret code will be unique.”_|
|2|**Server → Client**|**ServerHello**: Server chooses one cipher suite, sends its own random value, and provides its **digital certificate** (signed by a trusted CA).|Shopkeeper replies: _“Let’s use English. Here’s my government-issued ID to prove I’m legit. Also, here’s my random phrase.”_|
|3|**Client ↔ Server**|**Authentication & Key Exchange**: Client verifies the server’s certificate with a CA. Then both exchange key information (RSA or Diffie-Hellman/ECDHE) to generate a **shared secret**.|You check the shopkeeper’s ID against government records. Then you both agree on a secret handshake/code.|
|4|**Client ↔ Server**|**Session Key Creation**: Using both random values + shared secret, they generate the same **symmetric session key** (for fast encryption).|You and the shopkeeper now invent a secret language only both of you can understand.|
|5|**Client ↔ Server**|**Finished Messages**: Both sides confirm that encryption is active and ready. From now on, all communication is **encrypted with the session key**.|You both say: _“Okay, from now on, only secret code!”_ and start talking secretly.|

![](../attachments/Pasted%20image%2020250909131946.png)

### FTP
- file transfer protocol 
- layer 7
- TCP 21 (control/command)or TCP 20 (data transfer)
- Insecure (data, including credentials, is sent in plaintext) → replaced by **SFTP** (uses SSH) or **FTPS** (FTP with TLS).
- can require a uname/password or allow anonymous access

#### How FTP Works
- When you connect to an FTP server:
    - **Port 21 (Control Channel):** Used for sending **commands** like `ls`, `cd`, `get file.txt`.
    - **Port 20 (Data Channel):** Used for sending **actual files or directory listings**
👉 Unlike HTTP (single connection), FTP **always uses two connections**.

#### FTP modes

**Active mode** (default)
- client tells use this port and send data
- server initiates the data connection form its port 20 to the client's chosen port
- problem :firewalls can block the connection

**Passive Mode (PASV)**
- client says i cant accept incoming connections please tell me which port youll listen on and ill connect to you
- then the server will respond with ip and port
- works better with firewalls/NAT

#### Security Note
- **FTP = plaintext** → usernames, passwords, and files can be sniffed.
- Safer alternatives:
    - **SFTP** (SSH File Transfer Protocol) → Runs over SSH (port 22).
    - **FTPS** (FTP Secure) → FTP + TLS/SSL.



So FTP is like an **old pizza delivery system:**
- Active mode: Pizza guy comes to you.
- Passive mode: You go pick it up.
- But the whole conversation is overheard by neighbors (plaintext), unless you switch to SFTP/FTPS.

![](../attachments/Pasted%20image%2020250909133510.png)

gree -> command channel
blue -> responses sent back for FTP server

[FTP Docs](https://datatracker.ietf.org/doc/html/rfc959)

#### FTP Commands

|**Command**|**Description**|
|---|---|
|`USER`|specifies the user to log in as.|
|`PASS`|sends the password for the user attempting to log in.|
|`PORT`|when in active mode, this will change the data port used.|
|`PASV`|switches the connection to the server from active mode to passive.|
|`LIST`|displays a list of the files in the current directory.|
|`CWD`|will change the current working directory to one specified.|
|`PWD`|prints out the directory you are currently working in.|
|`SIZE`|will return the size of a file specified.|
|`RETR`|retrieves the file from the FTP server.|
|`QUIT`|ends the session.|
### SMB
- server message block
- An **application-layer protocol** for **sharing files, printers, and other resources** across a network.
- Mostly used in **Windows environments**, but supported by Linux/macOS too.
- **Connection-oriented** → relies on **TCP** (handshake, acknowledgments, etc.).

#### Ports Used
- **TCP 445** → Modern SMB (direct over TCP).
- **TCP 139** → SMB over NetBIOS (older).
- **UDP 137/138** → NetBIOS Name Service & Datagram Service (legacy).
- **SMB over QUIC** → Newer, secure transport (TLS encrypted).

![](../attachments/Pasted%20image%2020250909134047.png)

orange - establishes a session
blue - destination 
green - info field

---
---
