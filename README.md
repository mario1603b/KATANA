
<p align="center">
  <img src="https://raw.githubusercontent.com/mario1603b/KATANA/main/assets/katana-banner.png" width="900" alt="KATANA Banner">
</p>

<h1 align="center">⚔️ KATANA v5.2 Enterprise Edition</h1>
<h3 align="center">Threat Intelligence, Reporting & Active Defense Platform</h3>

<p align="center">
Advanced SOC Analysis Tool for Sophos Firewall Logs
</p>

<p align="center">
<img src="https://img.shields.io/badge/python-3.9+-blue.svg">
<img src="https://img.shields.io/badge/platform-Windows-lightgrey">
<img src="https://img.shields.io/badge/gui-CustomTkinter-green">
<img src="https://img.shields.io/badge/firewall-Sophos_API-orange">
<img src="https://img.shields.io/github/license/mario1603b/KATANA">
<img src="https://img.shields.io/github/stars/mario1603b/KATANA">
<img src="https://img.shields.io/github/forks/mario1603b/KATANA">
</p>

---

# ⚔️ KATANA v5.2 — Overview

KATANA is a **Threat Intelligence and Active Defense platform** designed for **SOC analysts, incident responders, and cybersecurity architects**.

The tool analyzes **Sophos Firewall logs**, extracts attacker intelligence, visualizes attack patterns, generates executive forensic reports, and can **actively mitigate threats by grouping and blocking attackers directly via the Sophos Firewall API**.

KATANA bridges the gap between:

* 🔎 **Forensic Log Analysis**
* 📊 **Threat Intelligence Visualization**
* 📄 **Executive PDF Reporting**
* 🛡️ **Automated Active Defense**

---

# 🚀 Core Capabilities



KATANA combines log forensics, threat intelligence, and automated defense into a single, highly optimized desktop platform. 

### ⚡ v5.2 Enterprise Updates
* **Multithreaded Architecture:** Heavy computations (Pandas, API requests) are decoupled from the UI thread, ensuring a 100% fluid and responsive interface without freezing.
* **API Independence:** Built for speed and reliability. Removed third-party rate-limited APIs (like VirusTotal/AbuseIPDB) to guarantee instant offline forensics.
* **Dynamic UI State Management:** Intelligent interface that guides the analyst, lighting up action buttons only when prerequisites are met.

---

# 🔍 Threat Intelligence Engine

Parses raw firewall logs and extracts attack intelligence in seconds.

### Features
* Universal Sophos CSV log parsing.
* Attacker IP extraction via Regex.
* Targeted username brute-force detection.
* Batch geographic localization (100 IPs per request).

---

# 📄 Executive Reporting & Visualization

Convert raw data into actionable deliverables for clients and management.


### Capabilities
* **One-Click PDF Export:** Automatically generates a comprehensive 2-page forensic report using `fpdf`.
* **Global Threat Mapping:** Interactive 2D/3D high-resolution topological heat map powered by Plotly.
* **Attack Distribution:** Matplotlib-powered charts showing top attacking countries and most vulnerable accounts.

---

# 🛡️ AEGIS Active Defense Engine

AEGIS allows **direct mitigation of malicious IP addresses** through the **Sophos Firewall API**, maintaining strict firewall hygiene.

### Smart Grouping Technology
Instead of polluting the firewall with scattered IP objects, AEGIS v5.2 automatically creates and updates a single `IPHostGroup` named **`KATANA_BLACKLIST`**. Administrators only need to configure a single drop rule for this group.

### Capabilities
* Direct Sophos Firewall XML/REST API integration.
* Automated IP Host creation and Group consolidation.
* Real-time mitigation terminal console.
* Threshold targeting (Top 10, Top 50, or Top 100 attackers).

---

# 📦 Installation

Clone the repository:

```bash
git clone [https://github.com/mario1603b/KATANA.git](https://github.com/mario1603b/KATANA.git)
cd KATANA
````

Install dependencies:

Bash

```
pip install -r requirements.txt
```

---

# ⚙️ Sophos Firewall Configuration

To allow KATANA's AEGIS engine to interact with the firewall:

1. Login to **Sophos WebAdmin**.
    
2. Navigate to: `Administration → Device Access`.
    
3. Enable **API Configuration**.
    
4. Add the **IP address of the machine running KATANA** to the allowed list.
    
5. Create a Firewall Rule at the top of your list dropping traffic from the Source Network: `KATANA_BLACKLIST`.
    

---

# 🧱 Build Portable Executable

You can compile KATANA into a **single portable Windows executable** that requires no Python installation.


```bash
pyinstaller --noconfirm --onefile --windowed --name "KATANA_v5.2_Enterprise" main.py
```

_Note: Large data-science libraries (Pandas, Plotly, Matplotlib) are bundled inside the `.exe`. The first launch may take 5-10 seconds as Windows decompresses the payload into memory._

---

# 🛠️ Technology Stack

|**Component**|**Technology**|
|---|---|
|**Language**|Python 3.9+|
|**GUI Framework**|CustomTkinter|
|**Data Processing**|Pandas|
|**Visualization**|Matplotlib / Plotly|
|**Reporting**|FPDF|
|**Concurrency**|Python Threading|
|**Networking**|Sophos XML API (`requests`)|

---

# ⚠️ Disclaimer

The **AEGIS Engine performs direct modifications to firewall configurations**. Use responsibly.

The authors are **not responsible for network outages, firewall misconfigurations, or unintended blocks** caused by automated mitigation. Always test in a **controlled environment** before production use.

---

# 📜 License

MIT License

---

# 👨‍💻 Author

Cybersecurity Research Project by **mario1603b**.

Focus areas: Threat Intelligence | Defensive Security | Security Automation
