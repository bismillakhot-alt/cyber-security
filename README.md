# 🛡️ CyberShield — Cybersecurity Monitoring Dashboard

> **Protect. Detect. Respond.**  
> A beginner-friendly security dashboard built with Python and Streamlit.

---

## 👤 Student Details

| Field           | Details                        |
|-----------------|--------------------------------|
| **Name**        | Your Name                      |
| **PRN / Roll No.** | XXXXXX                      |
| **College**     | Your College Name              |
| **Department**  | Computer Science / IT          |
| **Subject**     | Cybersecurity / Python Programming |
| **Date**        | June 2024                      |

---

## 📌 Project Overview

CyberShield is a single-file Python web app that simulates a real-world security
operations dashboard. It loads 20 fictional login records, automatically detects
suspicious IP addresses using a simple counting rule, and displays the results
with colour-coded charts, warning alerts, and interactive filters.

No machine learning. No real systems. Just plain Python `if` statements and Pandas.

---

## 🚀 Live URL

| Environment | URL |
|---|---|
| **Local (your machine)** | http://localhost:8501 |
| **Network (same Wi-Fi)** | `http://<your-ip-address>:8501` |

> To find your IP address on Windows run: `ipconfig` in the terminal.

---

## ⚙️ How to Run

### 1. Install dependencies
```bash
pip install streamlit pandas plotly
```

### 2. Start the app
```bash
streamlit run app.py
```

### 3. Open in browser
Streamlit will print:
```
Local URL:   http://localhost:8501
Network URL: http://192.168.x.x:8501
```
Open the **Local URL** in any browser. Click **🔄 Generate Sample Data** to load
the table, charts, and alerts.

---

## 📁 Project Structure

```
IBM project/
└── app.py          ← entire project in one file (~344 lines)
└── README.md       ← this file
```

### Sections inside `app.py`

| Section | What it does |
|---|---|
| Page config + CSS | Dark theme, browser tab title |
| Header | CyberShield title and subtitle |
| `SAMPLE_RECORDS` | 20 fictional login records (list of dicts) |
| Detection rule | Counts failures per IP; flags any IP with ≥ 5 |
| `assign_risk()` | Labels each row Low / Medium / High |
| Metric cards | 4 live summary numbers at the top |
| Charts (Plotly) | Success vs Failed + Failed by IP |
| Filter dropdowns | Filter by Result and Risk Level |
| Table + alerts | Colour-coded table + warning banners |

---

## ✨ Features

- **4 metric cards** — Total Logins, Successful, Failed, Suspicious Activities  
- **Brute-force detection rule** — flags any IP with 5+ failed logins  
- **3-tier risk labels** — Low 🟢 / Medium 🟠 / High 🔴 per login record  
- **Warning alerts** — plain-English explanation + recommended action  
- **Chart 1** — Login Outcome Comparison (Success vs Failed)  
- **Chart 2** — Failed Attempts by IP Address (attacker IP stands out in red)  
- **Filter by Login Result** — All / Success / Failed  
- **Filter by Risk Level** — All / Low / Medium / High  
- **Colour-coded table** — rows highlighted by risk level  

---

## 📊 Results (with sample data)

| Metric | Value |
|---|---|
| Total login records | 20 |
| Successful logins | 15 |
| Failed logins | 5 |
| Suspicious IPs detected | **1** (`192.168.4.77`) |
| High-risk rows | 5 |
| Medium-risk rows | 2 |
| Low-risk rows | 13 |

**Detected attack:** IP `192.168.4.77` made 5 failed attempts in under 90 seconds,
targeting usernames `admin`, `root`, and `sysadmin` — a classic brute-force pattern.

---

## 🔍 Detection Rule Explained

```python
SUSPICIOUS_THRESHOLD = 5   # change this to adjust sensitivity

for ip_address, fail_count in failed_counts.items():
    if fail_count >= SUSPICIOUS_THRESHOLD:
        suspicious_ips.append(ip_address)  # flag this IP
```

- Change `5` to `3` to flag IPs earlier (stricter).  
- Change `5` to `10` to allow more failures before flagging (looser).  
- No machine learning or external service is used.

---

## 🔒 Security Concepts Demonstrated

| Concept | How CyberShield shows it |
|---|---|
| Brute-force attack | IP 192.168.4.77 tries 5 username combos in 90 s |
| Threshold-based detection | `SUSPICIOUS_THRESHOLD = 5` |
| Risk classification | Low / Medium / High per record |
| Incident alert | Warning banner with recommended action |
| Log analysis | Table + charts mimic SOC analyst workflow |
| IP reputation | Repeated failures raise risk score |

---

## 📚 References & Links

| Resource | Link |
|---|---|
| Streamlit Documentation | https://docs.streamlit.io |
| Plotly Express Documentation | https://plotly.com/python/plotly-express |
| Pandas Documentation | https://pandas.pydata.org/docs |
| Deploy free (Streamlit Cloud) | https://share.streamlit.io |

---

## ⚠️ Limitations

- Data is static and fictional — not connected to a real log source
- Rule counts total failures only, not time-windowed failures
- No user authentication on the dashboard
- No persistent storage — resets on page refresh

---

## 🔮 Future Enhancements

- [ ] Connect to a live log file or SQLite database
- [ ] Time-window rule: 5 failures within 60 seconds
- [ ] Export flagged IPs to CSV
- [ ] Email / webhook alerts on detection
- [ ] Deploy publicly on Streamlit Community Cloud
- [ ] Add login page to restrict access

---

*Made with IBM Bob*
