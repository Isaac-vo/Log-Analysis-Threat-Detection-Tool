# Log Analysis & Threat Detection Tool

## About the Developer  
Hello everyone, my name is Isaac Venerucci de Oliveira. I’m a cybersecurity student and a passionate enthusiast for defending systems through smart detection and automation. Welcome to my fourth project out of the nine I’ve committed to building this year. Each project pushes the boundaries a little further, and this one dives into the world of real-time log analysis, anomaly detection, and behavioral threat hunting. Let’s unpack what this tool can do and how it works!

---

### Level  
Advanced

---

## Description  
The Log Analysis & Threat Detection Tool is a Python-based system that automates the detection of suspicious behavior in Windows Event Logs using a combination of rule-based logic and machine learning. It extracts relevant data, flags known malicious patterns (like failed logins and privilege escalation), and applies models like Isolation Forest and DBSCAN to uncover unknown anomalies. Whether you’re investigating brute-force attempts, unusual user behavior, or persistent attackers, this tool is designed to streamline your detection workflow and surface the most critical alerts.

---

## How Does It Work?

#### 1. Log Collection  
- Pulls Windows Event Logs ("Application", but customizable) via "win32evtlog" (For Windows OS).  
- Filters logs to include only the last 7 days for efficiency.  
- Extracts fields like **TimeGenerated**, **EventID**, **Source**, and **Message**.

#### 2. Suspicious Behavior Detection  
- Uses **regex patterns** to detect critical incidents, such as:  
  - Failed Logins  
  - Privilege Escalation  
  - Unauthorized Access  
  - Malware Traces
  - Others (You can customize which incidents you prefer)
- Flags **rapid-fire login attempts**, **persistent attackers**, and **brute-force indicators** based on time frequency and repetition.

#### 3. Stateful Threat Modeling  
- A built-in **event state machine** tracks the sequence of security events.  
- Raises alerts when suspicious patterns escalate (e.g., failed logins followed by privilege escalation).
This is a smart setting to maximize the identification of real potential incidents.

#### 4. Machine Learning Integration  
- Applies **Isolation Forest** to detect statistical anomalies in logs using features like "EventID" and "Message Length".  
- Uses **DBSCAN** clustering to detect dense behavioral clusters and mark outliers.  
- Supports multiple contamination levels for sensitivity tuning.
This combination enhance even more the detection of suspicious activities that drive out of the normal pattern.

#### 5. Visualization  
- Plots all detected suspicious events by hour to help identify hot zones of malicious activity.
Perfect for visual reading.

#### 6. Analysis  
- Saves all logs to **SQLite** ("event_logs" table).  
- Stores only flagged or anomalous entries in **flagged_events** for future auditing or review.

---

### Extra Features

**💻 Modular Design**  
Easy to adapt or extend with new detection rules or data sources.

**🧠 Dual Detection Model**  
Combines rule-based detection and unsupervised ML for broader coverage.

**📊 Lightweight Dashboard Potential**  
Future integration with a GUI or dashboard (e.g., Streamlit or Flask) is already scoped for expansion.

---

### Installation

1. **Clone the Repository**  
```bash
git clone https://github.com/Isaac-vo/log-threat-detector.git
```

2. **Install Dependencies**  
```bash
pip install -r requirements.txt
```

3. **Run the Tool**  
```bash
python log_analysis_and_threat_detection.py
```
>PS: After running the code above, wait a few seconds while the program runs and displays the results.

> ⚠️ *This script is intended for Windows-based machines with access to the Windows Event Log API.*

---

## How to Use It?

- Run the script in a PowerShell or CMD terminal with administrator privileges.  
- Review the output logs and alerts printed to the terminal.  
- Examine the `flagged_events` table in `windows_logs.db` for structured investigations.  
- Tune detection thresholds or add custom regex patterns for new threats.

---

## Support

If you have questions, suggestions, or just want to connect, feel free to reach out through GitHub or email me at **veneruci@gmail.com**.

Thank you for checking out this project! I hope it helps you dig deeper into the power of proactive defense through log intelligence.

Thank you! 06/16/2025!
