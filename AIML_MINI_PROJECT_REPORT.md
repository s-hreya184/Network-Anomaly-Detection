# AI-Powered Network Anomaly & Intrusion Detection System
### AIML Mini Project Report & Presentation Guide (Simplified / Layman Edition)

**Project Domain:** Artificial Intelligence & Machine Learning (AI/ML)  
**Main Machine Learning Algorithm:** Random Forest Classifier  
**Key Highlights:** 93% Accuracy, Explainable AI (XAI), What-If Simulator, Smart AI Assistant, Interactive FastAPI Web Dashboard  

---

## 1. Project Overview (In Simple Words)

### What does this project do?
Imagine a smart security guard standing at the gate of a computer network. Every time someone sends data over the internet (like browsing a website, sending an email, or downloading a file), this smart guard checks the connection and decides:
- **Is this Normal traffic?** (Safe, regular user)
- **Or is this an Attack / Anomaly?** (A hacker trying to crash the server, guess passwords, or spy on the system)

### Why are we using Machine Learning?
- **Old Rule-Based Systems:** Traditional antivirus or firewalls only look for known bad files (like a list of known criminals). If a hacker changes their attack just a little bit, the old system fails to detect it.
- **Our Machine Learning System:** Instead of memorizing fixed rules, our AI learns the *patterns* and *behavior* of normal network traffic versus malicious traffic. This allows it to spot strange, abnormal behavior even if it has never seen that exact attack before.
- **Explainable AI (No Black Box!):** Most AI models just say "Attack!" without explaining why. Our system shows an easy-to-understand percentage breakdown: *"Hey, 75% of my suspicion is because this connection is sending 1,000 packets per second, which is way too fast for a human!"*

---

## 2. The Features: What Does the AI Look At?

The AI evaluates **11 simple network features** for every connection. You can think of a network connection like a phone call or a postal parcel:

| # | Feature Name | What It Means (Simple Analogy) | Why the AI Cares |
|---|---|---|---|
| 1 | `duration` | **Call Duration**<br>How many seconds the connection lasted. | Normal web visits take 1–3 seconds. Port scans take 0.01 seconds (super fast). |
| 2 | `protocol` | **Language Spoken**<br>TCP (reliable chat), UDP (fast streaming), ICMP (ping checks). | Hackers prefer certain protocols for specific attacks. |
| 3 | `service` | **Door/Room Visited**<br>HTTP/HTTPS (Websites), SSH (remote login), DNS (address lookup). | Attackers try to break into specific doors like SSH or FTP. |
| 4 | `src_bytes` | **Words sent by the Caller**<br>Data sent from source to destination. | If someone sends huge amounts of data with no reply, it looks like a flood attack. |
| 5 | `dst_bytes` | **Words spoken back in Reply**<br>Data returned by the server. | When browsing a site, the server sends back big replies (images, pages). In an attack, reply is usually 0. |
| 6 | `src_packets` | **Number of letters/boxes sent**<br>Count of data packets from source. | A high packet count in a split second indicates an automated tool. |
| 7 | `dst_packets` | **Number of letters/boxes received back**. | Shows if the conversation was two-way or one-sided. |
| 8 | `src_dst_byte_ratio` | **Conversation Balance**<br>Ratio of bytes sent vs. received. | Balanced ratio = normal conversation.<br>Extreme ratio = one-sided attack. |
| 9 | `packets_per_second` | **Speed / Velocity of sending**<br>How many packets are sent per second. | A human might send 20–50 packets/sec. A botnet or DoS attack sends 1,000+ packets/sec. |
| 10 | `bytes_per_second` | **Bandwidth speed**<br>How much data volume passes per second. | Unusually high transfer rates flag data theft or server flooding. |
| 11 | `tcp_flags` | **Handshake Signals**<br>`SYN` = "Hello, let's talk"<br>`ACK` = "Got your message"<br>`RST` = "Hang up / Reset" | Sending thousands of `SYN` greetings without waiting for an answer is a classic SYN-Flood attack. |

---

## 3. Data Preprocessing (Teaching the AI to Read the Data)

Before training the machine learning model, raw data must be cleaned and converted into numbers:

```
[Raw Traffic Data] 
       ↓
1. Data Cleaning (Remove missing values, reject negative/impossible numbers)
       ↓
2. One-Hot Encoding (Convert words like 'TCP', 'HTTP' into numbers: 1s and 0s)
       ↓
3. Feature Scaling (Bring all numbers into the same standard scale so big numbers don't dominate)
       ↓
[Clean Data Ready for AI]
```

1. **Handling Text (One-Hot Encoding):** Machine learning models only understand numbers, not words. So we convert categories like `TCP` or `UDP` into binary numbers (e.g., TCP = `[1, 0]`, UDP = `[0, 1]`).
2. **Feature Scaling (StandardScaler):** Some numbers are huge (like `bytes_per_second = 80,000`) while others are small (like `duration = 0.05`). If we don't scale them, the model will think the big numbers are more important just because they are bigger. Scaling puts all numbers on an equal playing field.
3. **Data Cleaning:** Removes empty values and ensures no physically impossible values (like negative seconds or negative bytes) can fool the system.

---

## 4. The Machine Learning Model: Random Forest

### What is a Decision Tree?
A Decision Tree is like a game of **20 Questions**. It asks yes/no questions to reach a conclusion:
- *Is packets per second > 500?* → **Yes**
- *Is the TCP flag 'SYN'?* → **Yes**
- *Is destination bytes near 0?* → **Yes**
- **Decision:** This is a **DoS Attack**!

### Why Random Forest? (A Forest of 100 Trees)
A single decision tree can be biased or make mistakes on new data (called *overfitting*). 
- A **Random Forest** creates a team of **100 different decision trees**.
- Each tree is trained on slightly different samples of data.
- When a new network connection arrives, **all 100 trees vote**.
- The majority vote becomes the final prediction!
- **Analogy:** It’s like asking 100 cybersecurity experts instead of asking just 1. Even if a few make a mistake, the team decision is reliable and accurate.

### The 7 Classes the AI Detects:
1. **Normal:** Regular safe user activity (watching YouTube, browsing websites).
2. **DoS (Denial of Service):** Sending thousands of fake requests to crash a server.
3. **Probe:** A hacker scanning network ports to see which doors are unlocked.
4. **Botnet:** A computer secretly controlled by a virus talking to its master server.
5. **Brute Force:** A bot trying thousands of passwords on an SSH/login page.
6. **Web Attack:** Exploits targeting website vulnerabilities (like SQL Injection).
7. **Other:** Unusual protocol behavior that doesn't look normal.

---

## 5. Model Results & Performance (Very Simple!)

Our Random Forest model was tested on a benchmark dataset of over 1,000 real-world simulated network flows:

| Evaluation Metric | Score | What It Means to Your Teachers |
|---|---|---|
| **Accuracy** | **93.00%** | Out of 100 network connections, the AI correctly identifies 93 of them. |
| **Macro F1-Score** | **88.69%** | Shows that the model is balanced. It doesn't just guess "Normal" every time; it genuinely catches rare attacks too. |
| **Detection Speed** | **< 2 milliseconds** | The AI makes its decision almost instantly, fast enough for real-time traffic. |

---

## 6. The Special AI Features (What Makes Our Project Stand Out!)

### Feature 1: Explainable AI (XAI) — "Why did you say that?"
- **The Problem:** In most AI projects, the model is a "black box". It says "Danger!" but cannot explain why.
- **Our Solution:** For every prediction, our system calculates **Feature Attribution** (using Shapley-style math).
- **Output:** It shows an easy horizontal bar chart and a simple sentence:  
  > *"Flagged as DoS threat primarily because packet speed was 1,125 pkts/sec and TCP flag was SYN."*

### Feature 2: What-If Simulator — "What if we change this number?"
- Analysts can tweak sliders and inputs in real time:
  - *"What if we reduce packets per second from 1,000 down to 30?"*
  - The AI instantly re-evaluates and shows: **"Decision changed from DoS (96% confidence) to Normal (92% confidence)!"**
- This proves to teachers that the AI has truly learned the boundary between safe and dangerous traffic.

### Feature 3: Smart AI Assistant (Chatbot)
- If a teacher asks: *"How does a regular person understand this attack?"*
- You can show the **AI Copilot** tab. You type: *"Explain this threat in simple words and tell me how to block it."*
- The AI explains the threat and even provides the exact command needed to block the attacker.

---

## 7. The Web Dashboard (Built with FastAPI)

Instead of running code in a black command prompt, we created a clean, modern web dashboard. We used **FastAPI** to connect our Machine Learning model directly to the web page.

### The 5 Simple Tabs on the Dashboard:
1. **Single Flow Classifier:**
   - Type in the 11 numbers, OR simply click a preset button (like *"SYN Flood Attack"* or *"Normal Web Browsing"*).
   - Click **Classify** → Instantly see the prediction badge (Normal or Attack), confidence %, and the colorful explanation chart.
2. **Batch CSV Evaluation:**
   - Drag and drop an entire Excel/CSV file with 1,000 connections at once.
   - The AI processes all 1,000 rows in less than a second and displays:
     - Total normal vs. attack counts.
     - A colorful donut chart showing attack types.
     - A table listing every connection with its risk level.
3. **What-If Simulator:**
   - Change a few numbers to see how the AI's mind changes live on screen.
4. **Security Alerts Log:**
   - A history table that automatically saves every attack caught by the system so nothing is lost.
5. **AI Assistant:**
   - A chat window where you can ask questions about the traffic and get advice.

---

## 8. Viva Voce / Teacher Questions & Easy Answers

Here are the exact questions your teachers or external examiners are most likely to ask, along with simple answers:

### Q1: What is the main objective of your project?
> **Answer:**  
> "Our objective is to build an intelligent network anomaly detection system using Machine Learning. It analyzes 11 basic features of network traffic to distinguish safe traffic from cyber attacks like DoS, Botnets, and Brute Force, and it explains *why* it made that decision so humans can easily understand it."

### Q2: Why did you choose Random Forest instead of Deep Learning or Neural Networks?
> **Answer:**  
> "Our network traffic data is structured tabular data (numbers and categories in columns), not images or audio. Machine learning research consistently shows that tree ensembles like Random Forest perform better than deep neural networks on tabular data. It achieves 93% accuracy, trains fast, doesn't overfit easily, and gives predictions in under 2 milliseconds."

### Q3: What is Explainable AI (XAI) and why is it needed here?
> **Answer:**  
> "Traditional AI is a black box that just gives an answer without reasons. In cybersecurity, if an AI wrongly blocks a CEO or a real customer, it causes big problems. Our XAI module tells the user the exact percentage contribution of each feature—for example, showing that 70% of the reason an attack was flagged was due to high packet velocity."

### Q4: What does your What-If Simulator do?
> **Answer:**  
> "The What-If Simulator lets us change one or two features—like changing packet speed or connection flags—while keeping everything else the same. It shows how the AI's confidence changes and helps us verify that the model has learned the correct decision boundaries."

### Q5: How did you prepare the data before giving it to the model?
> **Answer:**  
> "We used three main preprocessing steps:  
> 1. We removed empty values and invalid entries.  
> 2. We used **One-Hot Encoding** to convert text categories like protocol and service into numbers.  
> 3. We used **StandardScaler** to scale numerical features so large numbers don't unfairly dominate small numbers."

### Q6: Why did you use FastAPI for the dashboard?
> **Answer:**  
> "FastAPI is a modern, high-speed Python web framework. It allows our machine learning model to serve predictions asynchronously and connect smoothly to our web dashboard. It also automatically generates live documentation for testing our AI endpoints."

---

## 9. How to Start and Show the Project

Run this single command in your terminal:
```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```
Then open your browser at:
- **Dashboard:** [http://localhost:8000](http://localhost:8000)
- **API Test Page:** [http://localhost:8000/docs](http://localhost:8000/docs)
