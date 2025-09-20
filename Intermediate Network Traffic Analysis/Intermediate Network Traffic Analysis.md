![](../attachments/Pasted%20image%2020250911115323.png)

[notes](https://github.com/JoshPatlingrao/HTB-Intro-and-Intermediate-Network-Analysis)
## ARP spofing and Abnormality Detection

[How ARP works](https://www.youtube.com/watch?v=tXzKjtMHgWI)

- **ARP (Address Resolution Protocol)**: Translates an IP address (like `192.168.1.10`) into a MAC address (like `00:1A:2B:3C:4D:5E`).
- Every device keeps an **ARP cache** = a table mapping IP ↔ MAC.
- Example: _“Who has 192.168.1.1? Tell me your MAC address.”_

### ARP Poisoning & Spoofing

[ARP poisoning](https://www.youtube.com/watch?v=A7nih6SANYs)

- If attacker doesn’t forward packets → ❌ Denial of Service (DoS).
- If attacker forwards packets → 🕵️ Man-in-the-Middle (MITM).
- **DNS spoofing** → redirect websites.
-  **SSL stripping** → remove encryption, steal data.

### Defenses
- static ARP entries
- Lock ports to specific MACs → blocks rogue devices.
- **Dynamic ARP Inspection (DAI):** Switch checks ARP packets for legitimacy.
- **Encryption (VPN/HTTPS):** Even if MITM happens, attacker can’t read data.

### Analysis

- install the tcpdump or wireshark in the end point
- `arp.opcode` = tells whether the ARP packet is a **request (1)**, **reply (2)**, or rare variants (3/4).
- It’s a key field for spotting **suspicious ARP traffic** in Wireshark.
- Lots of **unsolicited ARP replies (`opcode = 2`)** may indicate an attack

![[Pasted image 20250911131529.png]]
 `08:00:27:53:0C:BA is behaving suspiciously`. and its ip is `192.168.10.4` this is also has one more MAC `50:eb:f6:ec:0e:7f`

```shell
#we can conform the ip of both mac address weather its using same IP
arp -a | grep 50:eb:f6:ec:0e:7f
```

`arp.duplicate-address-detected` is a Wireshark flag that triggers when **two different MAC addresses claim ownership of the same IP address**, signaling a possible conflict or ARP spoofing.

**find all ARP activity for that IP and MAC**

```r
arp && (arp.dst.proto_ipv4 == 192.168.10.4 || arp.src.proto_ipv4 == 192.168.10.4)
```

**Track the two suspicious MACs:**

`eth.addr == 08:00:27:53:0c:ba or eth.addr == 50:eb:f6:ec:0e:7f`

```r
(arp.opcode) && ((eth.src == 08:00:27:53:0c:ba) || (eth.dst == 08:00:27:53:0c:ba))
```

---
---

## ARP Scanning & Denial-of-Service

first filter we need to use is `arp.opcode==2`

then we can use
`arp.opcode == 2 && arp.duplicate-address-detected`

### Responding To ARP Attacks

1. `Tracing and Identification`: First and foremost, the attacker's machine is a physical entity located somewhere. If we manage to locate it, we could potentially halt its activities. On occasions, we might discover that the machine orchestrating the attack is itself compromised and under remote control.
2.  `Containment`: To stymie any further exfiltration of information by the attacker, we might contemplate disconnecting or isolating the impacted area at the switch or router level. This action could effectively terminate a DoS or MITM attack at its source.

---
---

## 802.11 Denial of service

- we should also need to carefully examine link-layer protocols
- One common threat at this layer is **attacks against 802.11 (Wi-Fi)**, which fall under link-layer attacks
- to capture wireless or 802.11 we need WIDS/WIPS system or wireless interface 

enumerate wireless interface `iwconfig`
`airmon-ng` is a helper from the **Aircrack-ng** suite that makes it easy to put a Wi-Fi interface into **monitor mode** (the mode you need to capture _all_ 802.11 traffic).
- Often creates a new interface name (e.g. `wlan0` → `wlan0mon`) so you can run capture tools against it.
    
- Prints driver/chipset info and warns about processes that interfere.

```shell
sudo airmon-ng start wlan0
```

Secondly, using system utilities, we would need to deactivate our interface, modify its mode, and then reactivate it.

```shell
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up

#check weather its in monitor mode
iwconfig
```

**Why we use this command:**  
To _capture all wireless frames_ for a specific AP (BSSID) on channel 4 and save them to disk for later analysis (Wireshark / aircrack etc.).
**What “passively captures” means (one line):**  
The tool only _listens_ to the air — it records traffic without sending any packets or interacting with the network.
**What “hopping channels” means (one line):**  
Channel hopping means the capture interface automatically switches between Wi-Fi channels to see multiple networks; locking to one channel (-c) stops that so you don’t miss frames from your target AP.

```shell
sudo airodump-ng -c 4 --bssid F8:14:FE:4D:E6:F1 wlan0 -w raw
```

**One-line, one-line explanations of each piece of the command**
- `sudo` — run the command as root (required for raw wireless capture).
- `airodump-ng` — the program that listens to 802.11 traffic and logs APs/clients.
- `-c 4` — stay only on **channel 4** (don’t hop channels).
- `--bssid F8:14:FE:4D:E6:F1` — focus on and show traffic for this specific AP (by MAC).
- `wlan0` — the monitor-mode wireless interface to use (use `wlan0mon` if created by airmon-ng).
- `-w raw` — write captured data to files with the prefix `raw`.


A **deauthentication** attack is when an attacker pretends to be your Wi-Fi router and sends fake “disconnect” messages to kick devices off the network, usually to capture handshakes or cause disruption.
- capture WPA handshake
- cause denial of service 
- force users onto attacker's network

### finding deauthentication attack

- `wlan.bssid == xx:xx:xx:xx:xx:xx` so mainly focus on the AP mac
- `(wlan.bssid == xx:xx:xx:xx:xx:xx) and (wlan.fc.type == 0) and (wlan.fc.type_subtype == 12)` filter for deauth frame `wlan.fc.type == 0` management frame (they control how client join/leave) and its subtype is 12 for deauthentication 
-  so basically we are seeing teachers notes for the ones who told to leave
- basically by seeing the traffic the teacher is shouting to leave so we need to see which student left
- reason code is where reason for kick the student out `(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 7)`

### Revolving Reason Codes

- Smart attackers **change reason codes** instead of always using code 7.
- Example sequence: code 1 → code 2 → code 3, etc.
- This avoids triggering simple detection rules in a WIDS/WIPS.

**Wireshark filters (incrementing codes):**

- Reason code 1:
    `... and (wlan.fixed.reason_code == 1)`
- Reason code 2:
    `... and (wlan.fixed.reason_code == 2)`
- Reason code 3:
    `... and (wlan.fixed.reason_code == 3)`

**Analogy:**  
Instead of always using the excuse _“class expired”_, the prankster teacher mixes excuses:

- “You’re noisy” (code 1)
    
- “Wrong classroom” (code 2)
    
- “Homework missing” (code 3)
    

This makes it harder for hall monitors (WIDS) to catch the prank.

### Defenses Against Deauth Attacks

1. **Enable IEEE 802.11w (Management Frame Protection)**
    
    - Adds a “signature” to management frames → clients can verify they’re real.
        
    - Prevents attackers from forging deauth messages.
        
2. **Use WPA3-SAE**
    
    - Modern Wi-Fi security protocol → stronger protection against handshake attacks.
        
3. **Update WIDS/WIPS rules**
    
    - Ensure intrusion detection/prevention systems look for unusual patterns (not just code 7).
        

---

### 5. Failed Authentication / Association Attempts

- Attackers may try to **brute-force or flood** by repeatedly attempting to join your Wi-Fi.
    
- Results: **excessive association requests** from one device.
    

**Wireshark filter for association requests:**

`(wlan.bssid == F8:14:FE:4D:E6:F1)  and (wlan.fc.type == 00)  and ((wlan.fc.type_subtype == 0) or (wlan.fc.type_subtype == 1) or (wlan.fc.type_subtype == 11))`

**Meaning:**

- Type 00 = Management frames.
    
- Subtypes:
    
    - `0` = Association Request.
        
    - `1` = Association Response.
        
    - `11` = Authentication.
        

**Analogy:**  
Like a student keeps trying to enter the classroom again and again, knocking on the door repeatedly. If you see too many knocks, it’s suspicious.


`wlan.fc.type_subtype == 8` used to find the AP

---
---

## Rogue Access Point & Evil-Twin

- **Rogue AP** → An unauthorized Wi-Fi access point that is **plugged into your real network**, giving outsiders a hidden way inside.
    
- **Evil Twin** → A **fake Wi-Fi with the same name (SSID)** as yours, tricking users into connecting so attackers can steal data or credentials.

### Detect

look for multiple entries with the same ESSID but different BSSID
```bash
sudo airodump-ng -c 4 --essid HTB-Wireless wlan0 -w raw
```

- OPN meaning its open
- **Beacon frame** = the AP’s loudspeaker announcement: “I’m _X_ (SSID), I’m here, this is my ID (BSSID) and these are my rules (RSN).”

```scss
(wlan.fc.type == 00) and (wlan.fc.type_subtype == 8)
```

then check for RSN
**RSN info** = the “rules and security” card the AP hands to students (what encryption/ciphers it supports).
- **RSN / Cipher suite**: legit AP should advertise WPA2/WPA3 + ciphers (AES/CCMP). If the suspicious AP’s RSN is **missing** or different (e.g., open), that’s a red flag.
    
- **Vendor-specific info**: the legitimate vendor often includes vendor tags; attacker APs frequently omit or differ here.
- **Supported rates, HT/VHT capabilities, BSS load, country info**: subtle differences can show a fake AP.

### Finding a Fallen User

filter out the attacker MAC
```
wlan.bssid == f8:14:fe:4d:e6:f2
```


---
---
## Fragmentation Attacks

- Its job is to take a packet (like a letter), put a sender and receiver address on it, and make sure it gets forwarded hop by hop until it reaches the destination.
postoffice example
👉 Key point: IP **only delivers**, it doesn’t check if the packet is lost, broken, or reordered — that’s the job of the **transport layer** (like TCP).

### Important IP fields
#### 1. **Header Length**

- Tells how long the “envelope header” is.
    
- Analogy: Some envelopes have extra stamps or markings; this tells the receiver _how much space the address/stamps part takes up_.
#### 2. **Total Length**

- The size of the whole IP packet (header + data).
    
- Analogy: It’s like writing “this package weighs 2 kg” on the box, so the postal worker knows the total size.
#### 3. **Fragment Offset**

- When a packet is too big to travel in one piece, IP breaks it into smaller fragments.
    
- The **offset** tells how to reassemble them.
    
- Analogy: Imagine a big book mailed in several envelopes. Each envelope says _“this is part 2, continues after page 50.”_ That way, the receiver can put the book back together.
#### 4. **Source and Destination IP Addresses**

- These are like the **return address** (source) and the **destination address** (where the letter is going).
    
- Without them, the network wouldn’t know where the packet came from or where it’s headed.

An attacker can cut the poster into weird pieces (tiny pieces, overlapping pieces, missing pieces) so the mailroom (IDS/firewall) can’t inspect it properly, but the receiver (victim host) still glues it back together and reads the malicious content.

### How attackers abuse fragmentation (plainly)

1. **IDS/Firewall Evasion** — Split a malicious payload across fragments so the IDS that doesn’t reassemble never sees the complete exploit.
    
2. **Firewall Evasion** — Same idea but to bypass firewall rules that look at whole packet payloads.
    
3. **Resource exhaustion** — Send _lots_ of tiny fragments to overwhelm the IDS/firewall’s reassembly buffers.
    
4. **Fragment overlap / malformation** — Send fragments with overlapping byte ranges or odd offsets to confuse reassembly logic and bypass detection or crash old hosts.
    
5. **Oversized reassembly** — Craft fragments that, when reassembled, claim a huge size ( > 65535 ) to crash or DoS old stacks.

### Finding Irregularities in Fragment Offsets

attacker will use
```
nmap IP
nmap -f 10 IP
```

Seeing a ton of fragmentation from a host can be an indicator of this attack
However, the more notable indicator of a fragmentation scan, regardless of its evasion use is the single host to many ports issues that it generates.

In this case, the destination host would respond with RST flags for ports which do not have an active service running on them (aka closed ports).

---
---
## IP source and destination spoofing attacks

**IP source/destination spoofing** = attacker fakes the IP address in packets (source and/or dest) to hide where traffic really came from or to cause other hosts to respond to a victim.

**why they do**
- **Hide their identity / bypass filtering** (decoy scanning): pretend to be someone else so firewalls allow traffic.
    
- **Amplify attacks / DDoS** (random source, Smurf): make many machines reply to the victim by forging the victim’s IP as the source.
    
- **Crash or confuse hosts** (LAND): set source = destination so the target receives a packet that appears to be from itself.
    
- **Generate traffic patterns / cryptographic attacks** (IV generation): craft packets to produce repeated patterns attackers need for attacks (old wireless attacks).

### Practical indicators in traffic (what to look for)

1. **Source IP from outside your subnet on incoming** — if you’re on 192.168.1.0/24 and you see an incoming packet claiming to be from 10.0.0.5, be suspicious.
    
2. **Outgoing packets with source IP not in your subnet** — if a host inside your LAN sends a packet whose source IP isn’t in your LAN, it might be spoofing or misconfigured.
    
3. **Many packets where source == victim (Smurf/LAND)** — lots of replies landing on the same IP that never sent requests.
    
4. **Lots of traffic with random spoofed IPs to same destination/port** — classic for DDoS or scanning attempts.
    
5. **Unexpected protocols coming from internal hosts** — e.g., internal host sending raw ICMP floods with funny source addresses.
    
6. **Repeated identical payloads/frames** — might indicate automated spoofing or IV generation attempts.

### Finding Decoy Scanning Attempts
Simply put, when an attacker wants to gather information, they might change their source address to be the same as another legitimate host, or in some cases entirely different from any real host.

1. `Initial Fragmentation from a fake address`
2. `Some TCP traffic from the legitimate source address`
3. ` Secondarily, in this attack the attacker might be attempting to cloak their address with a decoy, but the responses for multiple closed ports will still be directed towards them with the RST flags denoted for TCP.`

**Defence**
1. `Have our IDS/IPS/Firewall act as the destination host would` - In the sense that reconstructing the packets gives a clear indication of malicious activity.
    
2. `Watch for connections started by one host, and taken over by another` - The attacker after all has to reveal their true source address in order to see that a port is open. This is strange behavior and we can define our rules to prevent it.

### Finding Random Source Attacks

- in which many hosts will ping one host which does not exist, and the pinged host will ping back all others and get no reply.
- We should also consider that attackers might fragment these random hosts communications in order to draw out more resource exhaustion.
- However in many cases, like LAND attacks, these attacks will be used by attackers to exhaust resources to one specific service on a port. Instead of spoofing the source address to be the same as the destination, the attacker might randomize them.

In this case, we have a few indicators of nefarious behavior:

1. `Single Port Utilization from random hosts`
2. `Incremental Base Port with a lack of randomization`
3. `Identical Length Fields`

### Finding Smurf Attacks
- SMURF Attacks: Attackers send ICMP packets with the victim’s IP as the source, prompting many replies that overwhelm the victim
    
    - A type of DDoS attack where random hosts overwhelm a victim host
    - How?
        - The attacker sends ICMP requests to many live hosts, faking the source IP as the victim’s IP
        - The live hosts reply to the victim with ICMP responses
        - This floods the victim, causing resource exhaustion
    - Detection
        - Excessive ICMP replies from one or more hosts to the victim
        - Many different hosts pinging a single victim host
    - Fragmentation can be incorporated to accelerate resource exhaustion
- Initialization Vector Generation: In older wireless networks, attackers modify the source and destination IP addresses of captured packets and send it again to generate initialization vectors to build a decryption table for a statistical attack. Look for excessive repeated packets between hosts.