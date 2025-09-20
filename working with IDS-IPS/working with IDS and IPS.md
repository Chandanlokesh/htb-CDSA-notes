
![](../attachments/Pasted%20image%2020250918190617.png)

## Introduction To IDS/IPS

`Intrusion Detection Systems (IDS)` and `Intrusion Prevention Systems (IPS)`

- An `IDS` is a device or application that monitors network or system activities for malicious activities or policy violations and produces reports primarily to a management station.
- IDS will only do the alerting 
- It looks for signs of malicious activity or policy violations and then **generates alerts** for security teams.
- Usually placed **behind the firewall** so it only sees traffic that has already passed the first layer of protection.
- 
- IDS will use two methods
	- signature-based detection : recognizes bad patterns . limited to known threats
	- anomaly- based detection : a baseline of normal behavior 

`IPS (Intrusion Prevention System)`
- **network security device** that sits in-line with network traffic (typically behind a firewall) and **monitors, detects, and actively blocks malicious activities in real time**.
- Once traffic passes the firewall, it then goes through the **IPS inline**, which looks for **deeper threats** (like malware, exploits, or anomalies).
🌍 Internet → 🔥 Firewall → 🛡 IPS → 🖥 Internal Network

**Host-based IDS/IPS (HIDS & HIPS)**
Instead of monitoring the entire network, these are installed on **individual computers/servers (hosts)**.

---
---

## Suricata fundamentals

- suricata is an opensource tool developed by the **OISF (Open Information Security Foundation)**.
- it works as IDS, IPS, NSM (network security monitoring tool) and IDPS (IDS + IPS)

**How it works**
- suricata relies on rules/signatures (like a checklist of known attack patterns)
- these rules tells suricata what to look for int the traffic
- it can also inspect the traffic at application layers not only raw packets

### Suricata — Inputs & Outputs

**offline Input (PCAP)**
Suricata reads previously captured network traffic stored in `.pcap` files (LibPCAP format).
Good for replaying attacks, testing new rules, doing post-mortem forensics, and safe experiments.

```bash
# process a pcap file and write logs into ./suricata-logs
suricata -r sample.pcap -c /etc/suricata/suricata.yaml -l ./suricata-logs
```

**Live capture via Libpcap**
Capture traffic directly from an interface (e.g., `eth0`) using libpcap. works in many os 
**Cons:** Lower performance than other options; single threaded in many setups; no builtin load balancing.

```bash
# live capture on interface eth0
suricata -i eth0 -c /etc/suricata/suricata.yaml -l /var/log/suricata

```

**AF_PACKET (Linux)**
- Linux kernel feature used by Suricata to capture packets at high speed using `PF_PACKET` sockets. has much better performance than libpcap and supports multi threading and mmap for speed