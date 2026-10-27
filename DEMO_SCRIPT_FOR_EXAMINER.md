# CyberGuard: Live Demonstration & Examiner Presentation Script

> **How to use this script:**  
> This script tells you **exactly what to say** (in quotes) and **exactly what to click on screen** (in brackets `[CLICK]`). Follow this step-by-step during your project demo for a smooth, confident, high-scoring presentation.

---

## 0. Pre-Demo Setup (Do This 5 Minutes Before the Examiner Arrives)

1. Open your terminal in the project folder and run:
   ```bash
   python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
   ```
2. Open your web browser and go to:
   **`http://localhost:8000`**
3. Ensure the browser is full-screen and zoomed comfortably (100% or 90% so all cards are visible).
4. Have the first tab (**Detection & Overview**) open on the screen.

---

## Phase 1: The Introduction (Time: ~1 to 1.5 Minutes)

*(Stand or sit beside your laptop. Look at the examiner, smile, and speak at a steady, confident pace.)*

> **You say:**  
> *"Good morning / afternoon, Sir / Ma'am.  
> 
> Our project is called **CyberGuard: Explainable AI Network Intrusion Detection System**.  
> 
> In computer networks today, thousands of data packets pass through every second. Traditional firewalls and antivirus tools rely on static signatures—meaning they only recognize attacks they have already seen in the past. If a hacker tweaks their attack even slightly, the firewall fails to detect it.  
> 
> To solve this, we built **CyberGuard**. It uses a **Machine Learning ensemble (Random Forest with 100 decision trees)** that learns the *behavior* and *statistical patterns* of network connections.  
> 
> Rather than snooping on private encrypted contents, it analyzes **11 flow telemetry features**—such as packet velocity, byte ratios, connection duration, and TCP flags—to classify traffic into **Normal activity or 6 distinct cyber attack types** with **93% accuracy** in **under 2 milliseconds**.  
> 
> Best of all, unlike standard AI models that act as opaque 'black boxes', CyberGuard includes **Explainable AI (XAI)** to explain *why* it flagged an attack, an interactive **What-If Simulator**, and an **AI Security Copilot** to give instant firewall remediation commands.  
> 
> Allow us to demonstrate how the system works live."*

---

## Phase 2: Live UI Demonstration (Step-by-Step)

---

### Step 1: Testing a Normal Web Connection
*(You are on the **Detection & Overview** tab. Scroll slightly so the **Single Network Flow Classifier** card is centered.)*

> **You say:**  
> *"First, let's look at how the system evaluates legitimate, everyday web browsing."*

* **[ACTION]** Click the preset button at the top: **`Normal Web Browsing (HTTP/HTTPS)`**

> **You say:**  
> *"When I click this preset, the 11 input fields are populated with real-world telemetry for safe browsing.  
> Notice that the protocol is TCP, the flag is ACK, packet speed is a modest 24 packets per second, and destination bytes (4,890) are higher than source bytes (1,420). This is completely normal because when a user visits a website, the server sends back pages and images.  
> Now let's classify it."*

* **[ACTION]** Scroll down and click the blue button: **`Classify Network Flow`**
* *(Wait 1 second for the result panel to appear below)*

> **You say:**  
> *"As you can see, the AI instantly gives its verdict:  
> - **Prediction:** Normal Traffic (marked with a green badge and Low Severity).  
> - **Confidence:** ~90%+.  
> - **Inference Latency:** Less than 2 milliseconds, making it fast enough for high-speed network traffic."*

---

### Step 2: Testing an Attack & Demonstrating Explainable AI (XAI)
*(Stay on the same tab)*

> **You say:**  
> *"Now, let's see what happens when an adversary launches a Denial of Service (SYN Flood) attack."*

* **[ACTION]** Click the preset button: **`SYN Flood / DoS Burst`**

> **You say:**  
> *"Notice how the numbers completely change:  
> 1. The packet speed spikes to over 1,100 packets per second.  
> 2. The TCP flag changes to `SYN` (requesting handshakes repeatedly without waiting).  
> 3. The server only replies with 120 bytes, because the server is getting choked.  
> Let's run the classification."*

* **[ACTION]** Click the blue button: **`Classify Network Flow`**
* *(Point at the red badge and the horizontal bar chart below it)*

> **You say:**  
> *"Immediately, the system flags this as **DoS** with **Critical Severity** and 98% confidence.  
> 
> But here is what makes our project stand out from ordinary ML projects: **Explainable AI (XAI)**.  
> Right below the badge, the system shows a feature attribution chart and a plain-English explanation:  
> It tells the security analyst: *'Flagged as DoS primarily because packet velocity was 1,125 pkts/sec and the TCP handshake flag was SYN.'*  
> 
> Furthermore, our **Counterfactual engine** calculates the exact threshold needed to make this connection safe—showing that if packet velocity dropped below 50 pkts/sec, the traffic would be classified as Normal. This removes the guesswork for network engineers."*

---

### Step 3: Batch CSV Dataset Evaluation (1,000+ Flows at Once)
*(Look at the top navigation bar)*

> **You say:**  
> *"In a real-world enterprise network, security teams don't just test one flow at a time; they analyze thousands of connections simultaneously. Let's switch to the Batch Evaluation tab."*

* **[ACTION]** Click the tab in the top navbar: **`Batch CSV Analysis`**
* **[ACTION]** Click the button on the top right: **`Load Benchmark Demo (1,000 Flows)`**  
  *(Alternatively, drag and drop `data/test_network_traffic.csv` onto the dropzone)*
* *(Wait 1–2 seconds for the cards and charts to render)*

> **You say:**  
> *"In less than a second, the model analyzed over 1,000 connection records:  
> - **Summary Cards:** We can see the total flows processed, how many were benign, how many were threats, and the overall detection rate.  
> - **Interactive Donut Charts:** Here we have a visual breakdown of attack distributions (DoS, Probe, Botnet, Brute Force, Web Attacks) and their severity tiers.  
> - **Inspection Table:** Below the charts is an interactive table showing each flow ID, its predicted attack category, severity tag, and confidence score.  
> - **Export Options:** Analysts can click 'Download Full CSV' or 'Download Summary Report' to export the incident data for security compliance audits."*

---

### Step 4: The What-If Traffic Simulator (Decision Boundary Testing)
*(Look at the top navigation bar)*

> **You say:**  
> *"A common question examiners ask is: 'How do you prove your AI hasn't just memorized the training data?'  
> To demonstrate that our model has truly learned mathematical decision boundaries, we built the What-If Simulator."*

* **[ACTION]** Click the tab in the top navbar: **`What-If Simulator`**
* *(Scroll down to Section 2: 'Modify Specific Attack Features')*

> **You say:**  
> *"Here, we have a baseline normal flow. In Section 2, we can artificially simulate attack behavior by tweaking specific parameters—for instance, increasing simulated packet velocity or switching the TCP flag to SYN."*

* **[ACTION]** Keep the default simulation values or tweak `Simulated Packets / Sec` to `850` and flag to `SYN`.
* **[ACTION]** Click: **`Run Simulation & Compare Delta →`**
* *(Point at the comparison result card that appears below)*

> **You say:**  
> *"The simulator compares the baseline against the modified flow side-by-side.  
> It shows how the prediction flipped from Normal to DoS, displays the confidence shift, and calculates an **Evasion Robustness score**. This proves that the model dynamically evaluates feature thresholds rather than static rules."*

---

### Step 5: Security Alerts Incident Ledger
*(Look at the top navigation bar)*

* **[ACTION]** Click the tab in the top navbar: **`Security Alerts`**

> **You say:**  
> *"Whenever a high or critical threat is detected anywhere in the system, it is automatically written to this persistent Security Incident Log.  
> It acts as a tamper-evident audit trail, storing the timestamp, threat type, severity level, and key trigger parameters so incident response teams have a historical record of all blocked attacks."*

---

### Step 6: AI SOC Copilot (Powered by Google Gemini)
*(Look at the top navigation bar)*

> **You say:**  
> *"Finally, once an attack is detected, a junior security analyst might not know the exact command needed to block it on a live Linux server or firewall. For this, we built the AI SOC Copilot."*

* **[ACTION]** Click the tab in the top navbar: **`AI SOC Copilot`**
* *(Point at the chat window and the suggested prompt chips)*

> **You say:**  
> *"This copilot is connected to Google Gemini and is context-aware—meaning it automatically knows about the last attack we just classified.  
> Let's ask it for an immediate remediation firewall rule."*

* **[ACTION]** Click the quick suggestion chip: **`Generate iptables Rule`**  
  *(Or type: `How do I block this DoS attack?` and click Send)*
* *(Wait for the response to stream in)*

> **You say:**  
> *"The Copilot analyzes the attack telemetry and instantly returns the exact Linux `iptables` drop commands, explains how the rule works, and suggests rate-limiting parameters.  
> Even if the internet connection is offline, the system includes a built-in local expert fallback so the security analyst is never left without guidance."*

---

## Phase 3: Conclusion & Handoff to Examiner (Time: ~30 Seconds)

*(Turn back to face the examiner)*

> **You say:**  
> *"To conclude, Sir / Ma'am:  
> CyberGuard provides an end-to-end, production-ready solution for modern network security. It replaces slow, rigid firewalls with a high-speed 93% accurate Random Forest model, solves the AI black-box problem through Explainable AI, and equips security teams with What-If simulations and automated Copilot playbooks.  
> 
> Thank you very much for your time. We are now happy to answer any questions you may have."*

---

## Phase 4: Examiner Q&A Quick Defense Sheet

Keep these short answers in mind if the examiner asks specific follow-up questions:

| Examiner Question | Your Winning Answer |
|---|---|
| **"Why Random Forest instead of Deep Learning / CNN?"** | *"Sir/Ma'am, our data is structured tabular flow metadata, not unstructured images or audio. Machine learning benchmarks consistently show tree ensembles outperform deep neural networks on tabular data. It also makes predictions in under 2 milliseconds, whereas neural networks take 50–100ms and introduce network lag."* |
| **"Is this analyzing live network packets right now?"** | *"Currently, it operates on captured bidirectional flow records (via CSV or JSON API). This offline design ensures zero packet-drop overhead on high-throughput networks. In our future work, we plan to integrate live packet sniffers like Zeek or libpcap."* |
| **"Why not inspect the packet payload content?"** | *"Over 90% of modern internet traffic is encrypted via HTTPS and TLS. Payload inspection cannot see inside encrypted packets and violates user privacy. Flow telemetry gives us an accurate behavioral signal that attackers cannot hide with encryption."* |
| **"What if your Gemini API key runs out or internet fails?"** | *"We built an automatic fallback mechanism in [`src/soc_copilot.py`](file:///c:/Users/Shreya/Documents/Network-Anomaly-Detection/src/soc_copilot.py#L54). If the Gemini API is unreachable, our local rule-based SOC expert engine generates the response and iptables rules offline."* |
| **"How did you handle unbalanced attack classes?"** | *"We evaluated the model using **Macro F1-Score (88.69%)**, which gives equal weight to rare attacks like Botnets and Brute Force, proving the model doesn't just guess the majority Normal class."* |
