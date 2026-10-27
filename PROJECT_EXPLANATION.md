# CyberGuard: Network Anomaly & Intrusion Detection System
## Examiner Presentation & Viva Guide

> **How to use this guide:**  
> This document is written in clear, natural language. You can read it directly to understand the project, show it to your external examiner, or use the exact sentences in Section 8 when answering questions during your demo.

---

## 1. Quick 2-Minute Project Summary (What to Say When You Begin)

> *"Good morning / afternoon, Sir / Ma'am.  
> Our project is called **CyberGuard**. It is an AI-powered Network Intrusion Detection System.  
> 
> In simple words, whenever computers talk to each other over the internet, they exchange data packets. Hackers often try to crash servers, guess passwords, or scan for vulnerabilities.  
> 
> Traditional firewalls only look for known attack signatures. If an attacker changes their method slightly, the firewall misses it. Our system uses a **Machine Learning model (Random Forest)** that learns the *behavior* of network traffic. By inspecting 11 basic features of a connection—like how fast packets are sent, which protocol is used, and how much data is exchanged—it can accurately classify traffic into **Normal activity or 6 different cyber attack categories** with **93% accuracy** in under 2 milliseconds.  
> 
> What makes our project different from typical ML projects is that it is not a black box:
> 1. It **explains why** it flagged an attack using Explainable AI.
> 2. It has an interactive **What-If Simulator** to test how changing traffic parameters affects the decision.
> 3. It includes an **AI Assistant (Copilot)** that gives the exact firewall commands to block the attacker.
> 4. Everything runs on a complete, interactive **Web Dashboard** built with FastAPI."*

---

## 2. The Problem We Are Solving

1. **Firewalls are too rigid:** Traditional firewalls work on fixed rules. If an attack doesn't match an exact rule on their list, it slips right past them.
2. **Most AI systems are "Black Boxes":** Many machine learning models just say *"Warning: Threat Detected!"* but cannot explain why. In real life, if an AI accidentally blocks a company CEO or an important customer, that causes serious business problems. Security teams need to see the reason before taking action.
3. **Most student projects stay in Jupyter Notebooks:** Typical college projects just train a model in a notebook, display a static graph, and stop there. We built a fully functioning web application with single flow analysis, batch CSV processing, and live threat logs.

---

## 3. How the System Works (Step-by-Step Flow)

When network traffic enters the system, here is the exact journey it takes:

```
[Network Traffic Data]
(Entered manually on screen or uploaded via a CSV file)
          │
          ▼
1. Data Validation:
   Checks that required columns exist and that numbers are realistic
   (e.g., rejecting negative durations or missing values).
          │
          ▼
2. Data Preprocessing:
   - One-Hot Encoding: Converts text categories ('TCP', 'HTTP') into numbers (0s and 1s).
   - Standard Scaling: Puts all numbers on an equal scale so large numbers 
     (like 50,000 bytes) don't unfairly overpower small numbers (like 0.05 seconds).
          │
          ▼
3. Random Forest Classification:
   An ensemble of 100 decision trees inspects the numbers. Each tree votes,
   and the majority vote decides the traffic type.
          │
          ▼
4. Risk & Severity Assignment:
   Assigns a threat level: Critical, High, Medium, or Low.
          │
          ▼
5. Explainability & What-If Engine:
   Calculates which features caused the alarm and what small adjustment 
   would make the connection safe again.
          │
          ▼
6. Web Dashboard & AI Copilot:
   Shows colorful charts, logs the incident, and lets you ask the AI assistant 
   how to block the attack.
```

---

## 4. The 11 Input Features Explained (In Plain Words)

Our model does not read private message content (which is encrypted anyway). Instead, it looks at the **metadata** of the connection—like looking at the envelope of a letter rather than opening the letter inside.

| # | Feature Name | What It Is | Why the AI Needs It |
|---|---|---|---|
| 1 | `duration` | Length of the connection in seconds. | **Scanners vs. Humans:** Port scans touch a port and quit in 0.01 seconds. Normal browsing lasts 1 to 5 seconds. |
| 2 | `protocol` | The protocol used: TCP, UDP, ICMP, or DNS. | **Attack Rules:** Certain attacks only happen on certain protocols. For example, SYN floods require TCP; ping floods use ICMP. |
| 3 | `service` | The service/door targeted: HTTP, SSH, FTP, DNS, etc. | **Target Context:** A burst of attempts on `SSH` indicates someone trying to break in (Brute Force). High traffic on `HTTP` is normal web browsing. |
| 4 | `src_bytes` | Bytes sent from the sender to the server. | **Outbound Volume:** Floods or malicious script uploads show unusually high source bytes. |
| 5 | `dst_bytes` | Bytes sent back from the server to the sender. | **Server Health:** When you open a website, the server sends back lots of data (HTML, images). In an attack, the server sends back 0 bytes because it's either overwhelmed or refusing to talk. |
| 6 | `src_packets` | Total number of data packets sent by the client. | **Packet Count:** DoS attacks blast thousands of small packets to choke the system, even if the total bytes are small. |
| 7 | `dst_packets` | Total number of packets returned by the server. | **Two-Way Check:** A healthy conversation is two-way. If `src_packets` is 1,000 and `dst_packets` is 0, someone is spamming without listening. |
| 8 | `src_dst_byte_ratio` | Ratio of bytes sent vs. bytes received (`src_bytes / dst_bytes`). | **Balance Indicator:** In normal web use, the server sends more than the user (ratio < 1). In an attack or data theft, the user sends far more than they receive (ratio >> 1). |
| 9 | `packets_per_second` | How fast packets are being transmitted (packet rate). | **Human vs. Bot:** A real person might generate 10 to 40 packets per second. An automated attack script easily pumps out 1,000+ packets per second. |
| 10 | `bytes_per_second` | Speed of data transfer (bandwidth used per second). | **Pipe Flooding:** Catches massive volumetric attacks trying to saturate the network connection. |
| 11 | `tcp_flags` | Digital handshakes (`SYN`, `ACK`, `RST`, `PSH-ACK`). | **Connection State:** A normal connection says hello (`SYN`), gets an answer (`SYN-ACK`), and confirms (`ACK`). Sending only `SYN` without completing the handshake is a classic SYN flood. Getting `RST` means closed doors. |

---

## 5. The 7 Traffic Categories Explained (In Plain Words)

The system classifies every connection into one of these 7 categories:

### 1. Normal (Safe Traffic)
* **What it is:** Everyday safe user activity—browsing websites, reading emails, or watching videos.
* **How it looks in data:** Completed two-way handshake (`SYN` $\rightarrow$ `ACK`), reasonable duration (a few seconds), normal packet speeds, and the server returns healthy data (`dst_bytes` is high).

### 2. DoS (Denial of Service)
* **What it is:** A digital stampede. An attacker floods a server with millions of fake connection requests so the server runs out of memory and crashes for real users.
* **How it looks in data:** Packet speed (`packets_per_second`) shoots above 1,000 pkts/sec, thousands of unilateral `SYN` requests are sent, and the server replies with 0 bytes.
* **Severity:** **Critical**

### 3. Probe (Port Scanning & Reconnaissance)
* **What it is:** A digital burglar walking down a street rattling all doorknobs and windows to find one that is unlocked. Hackers use tools like Nmap to scan which ports are open before attacking.
* **How it looks in data:** Super short duration ($< 0.05$ seconds), barely any data sent or received, and lots of `RST` (reset / connection closed) flags.
* **Severity:** **Medium**

### 4. Botnet (Compromised Machine / Zombie)
* **What it is:** A computer inside a network that has been infected by malware. It secretly calls home to the hacker’s "Command and Control" server to receive instructions or leak stolen data.
* **How it looks in data:** Regular periodic "heartbeat" signals (beaconing), abnormal DNS traffic, and bursts of outbound data transfer.
* **Severity:** **Critical**

### 5. Brute Force (Password Guessing)
* **What it is:** An automated script rapidly trying hundreds of common passwords (like `admin123`, `password`) against login services like SSH or FTP.
* **How it looks in data:** Traffic aimed specifically at remote login ports (`service: SSH` or `FTP`), rapid repetitive packets with `PSH-ACK` flags (pushing password strings), and small rejection replies.
* **Severity:** **High**

### 6. Web Attack (Website Exploits)
* **What it is:** Attacks aimed directly at website code and databases, such as SQL Injection (inserting database commands into login boxes) or Cross-Site Scripting (XSS).
* **How it looks in data:** Targets `service: HTTP` or `HTTPS`, but contains unusually long or strange request sizes (`src_bytes` is unusually high due to encoded scripts or SQL payloads).
* **Severity:** **High**

### 7. Other (Unusual / Corrupted Traffic)
* **What it is:** Traffic that does not fit standard profiles or violates networking rules (like malformed packets with illegal flag combinations).
* **Severity:** **Medium**

---

## 6. The Machine Learning Model: Random Forest

### What is it?
We use a **Random Forest Classifier** made up of **100 Decision Trees**.

* **What is a Decision Tree?** A decision tree is like a flowchart of yes/no questions:  
  *Is packet speed > 800?* $\rightarrow$ **Yes**  
  *Is TCP flag 'SYN'?* $\rightarrow$ **Yes**  
  *Are destination bytes near 0?* $\rightarrow$ **Yes**  
  *Decision:* **DoS Attack!**
* **Why a "Forest"?** A single decision tree can easily get confused by strange noise in the data (called *overfitting*). Random Forest creates **100 different trees**. When a connection comes in, **all 100 trees vote**. The majority vote wins!
* **Analogy:** It’s like consulting a panel of 100 cybersecurity experts instead of relying on just one person's opinion. Even if 3 or 4 make a mistake, the remaining 96 guarantee a reliable answer.

### Why Random Forest instead of Deep Learning / Neural Networks?
This is a favorite question for examiners. Here are the 3 concrete answers to give:
1. **Tree models win on tabular data:** Multiple AI research benchmarks show that tree ensembles (Random Forest, XGBoost) outperform deep neural networks on structured table data (numbers and categories in columns).
2. **Speed (< 2 milliseconds):** In cybersecurity, traffic flows at gigabits per second. A heavy neural network takes 50–100 milliseconds to calculate, creating a bottleneck. Our Random Forest predicts in under 2 milliseconds.
3. **No Overfitting & High Interpretability:** Neural networks are black boxes that require massive datasets. Random Forest trains fast, doesn't overfit easily, and lets us calculate exact feature importance.

### Model Performance Numbers
* **Accuracy:** **93.00%** (correctly classifies 93 out of 100 connections).
* **Macro F1-Score:** **88.69%** (proves the model catches rare attacks like Botnets and Brute Force, not just easy Normal traffic).
* **Prediction Time:** **< 2 milliseconds**.

---

## 7. What Makes Our Project Stand Out (Key Differentiators)

Most university intrusion detection projects are just a static Python script or Jupyter Notebook. CyberGuard provides 4 real innovations:

```
┌─────────────────────────────────────────────────────────────┐
│                   CYBERGUARD INNOVATIONS                    │
├──────────────────────────────┬──────────────────────────────┤
│ 1. Explainable AI (XAI)      │ 2. What-If Simulator         │
│ Shows the exact reason & %   │ Live sliders to see when     │
│ impact behind every alarm.   │ an attack turns into normal. │
├──────────────────────────────┼──────────────────────────────┤
│ 3. AI SOC Copilot (Gemini)   │ 4. Full Web Application      │
│ Suggests real firewall rules │ FastAPI dashboard, CSV batch │
│ (iptables) to block threats. │ upload, and alerts ledger.   │
└──────────────────────────────┴──────────────────────────────┘
```

1. **Explainable AI (No Black Box):** When our system catches a DoS attack, it doesn't just say "Threat". It shows a bar chart and says: *"Flagged as DoS primarily because packets per second was 1,120 and TCP flag was SYN."*
2. **What-If Simulator:** You can change a number on screen (e.g., lower packet rate from 1,000 to 40) and watch the AI's decision live change from "Attack (96%)" to "Normal (94%)". This proves the AI has genuinely learned real thresholds.
3. **AI SOC Copilot:** Powered by Google Gemini (with an offline expert fallback), this chat tab lets an analyst ask *"How do I stop this?"* and gets the exact terminal firewall command (`iptables -A INPUT -s <IP> -j DROP`) to block the hacker immediately.
4. **FastAPI Web Dashboard:** Runs as an interactive web page where anyone can test single connections or drag-and-drop a CSV file with 1,000 connections at once.

---

## 8. Viva Cheat Sheet: Top Examiner Questions & Exact Spoken Answers

Here are the questions your examiner is most likely to ask, along with the exact responses you can give:

### Q1: What is the main objective of your project?
> **Answer:**  
> *"Sir/Ma'am, our objective is to build an intelligent, explainable Network Intrusion Detection System. It inspects 11 flow metadata features to classify network traffic into Normal or 6 cyber attack types with 93% accuracy, and it explains the exact reason behind every decision."*

### Q2: Why did you look at flow metadata instead of the packet contents?
> **Answer:**  
> *"Over 90% of modern internet traffic is encrypted using HTTPS and TLS, so we cannot read the payload anyway. Looking at metadata—like packet speed, byte counts, and connection duration—is fast, respects user privacy, and works regardless of encryption."*

### Q3: Why did you choose Random Forest over Deep Learning?
> **Answer:**  
> *"Because network flow data is tabular structured data. Machine learning benchmarks show that tree ensembles like Random Forest perform better than deep neural networks on tabular data. It also predicts in under 2 milliseconds, which is critical for network speed, and it is easily explainable."*

### Q4: How does your preprocessing work?
> **Answer:**  
> *"We use three steps:  
> 1. We check for missing or negative values.  
> 2. We use **One-Hot Encoding** to convert text features like protocol ('TCP') into numbers (1s and 0s).  
> 3. We use **StandardScaler** so features with large numbers, like bytes per second, don't overpower small numbers, like duration."*

### Q5: What is Explainable AI and why is it important in cybersecurity?
> **Answer:**  
> *"Standard AI is a black box that gives an answer without reasons. In cybersecurity, if an AI wrongly blocks legitimate traffic, it halts business operations. Our XAI module shows the exact percentage contribution of each feature so human analysts can verify the decision before blocking an IP."*

### Q6: What does your What-If Simulator do?
> **Answer:**  
> *"It lets us modify one or two feature values while keeping the rest constant. For example, if we reduce packet rate on an attack flow, the simulator shows the exact point where the model flips from Attack to Normal. This helps us verify our model's decision boundaries."*

### Q7: What dataset did you use and what are its limitations?
> **Answer:**  
> *"We used a structured synthetic network flow benchmark dataset containing over 1,000 labeled connections across 7 classes. Its limitation is that it evaluates offline flow records rather than tapping into live raw network wire capture, which is our planned future enhancement."*
