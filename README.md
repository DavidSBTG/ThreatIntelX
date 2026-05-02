# 🧠 ThreatIntelX

## 📌 Overview

ThreatIntelX is a lightweight Threat Intelligence Dashboard designed for SOC Analysts to analyze IP addresses and domains using OSINT APIs.

The tool enriches indicators with real-time reputation data from external threat intelligence sources and provides a clear risk assessment.

---

## ⚙️ Features

* 🔍 IP & Domain Analysis
* 🌍 OSINT Enrichment (AbuseIPDB, VirusTotal)
* 🚨 Risk Scoring System (LOW / MEDIUM / HIGH)
* 📊 Visual Dashboard (Streamlit UI)
* 🧬 Malware & Reputation Insights
* 🧠 Analyst Summary for quick decision-making

---

## 🏗️ Architecture

**Frontend:**

* Streamlit (SOC-style dashboard)

**Backend Logic:**

* Python (Requests, OSINT APIs)

**Data Sources:**

* AbuseIPDB
* VirusTotal

---

## 🚀 Getting Started

### 1️⃣ Clone the repository

```bash
git clone https://github.com/DavidSBTG/threatintelx.git
cd threatintelx
```

---

### 2️⃣ Create virtual environment

```bash
python -m venv venv
.\venv\Scripts\activate
```

---

### 3️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

---

### 4️⃣ Configure API keys

Create a `.env` file:

```env
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

⚠️ Do NOT upload your `.env` file to GitHub

---

### 5️⃣ Run the application

```bash
streamlit run app.py
```

---

## 📸 Preview

*(Add screenshots here)*

```markdown
![Dashboard](screenshot.png)
```

---

## 🎯 Use Case

* SOC Analyst workflow simulation
* Threat hunting & enrichment
* Security investigation support

---

## 🧠 Skills Demonstrated

* Threat Intelligence Integration
* API Handling (REST APIs)
* Data Analysis & Visualization
* Security Awareness & Risk Evaluation
* Python Development

---

## 🔐 Security Note

This project uses API keys via environment variables to ensure secure handling of sensitive data.

---

## ⚡ Author

David Schünke
