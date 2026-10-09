# 🛡️ HoneyWatch — Honeypot Security Monitoring Dashboard

**A Python-based cybersecurity lab for network monitoring, security event analysis, and incident reporting.**

HoneyWatch is a defensive cybersecurity portfolio project that records connection attempts against a local TCP decoy service and visualizes the resulting activity through an interactive, SOC-inspired monitoring dashboard.

The project demonstrates foundational skills in network programming, event logging, data visualization, and security investigation workflows.

---

## ✨ Features

* 🍯 **TCP Honeypot** — Captures incoming test connections to a local decoy service.
* 📝 **Structured Event Logging** — Stores timestamps, source addresses, and destination ports in JSON Lines (JSONL) format.
* 📊 **Interactive Security Dashboard** — Visualizes connection activity, source IPs, and event statistics.
* 🚨 **Repeated-Source Alerts** — Flags sources that meet a configurable event-count threshold for further investigation.
* 🔎 **Event Filtering** — Filter records by time range, source IP, and severity classification.
* 📥 **CSV Export** — Download filtered event data for further analysis.
* 📄 **Incident Report Generator** — Creates downloadable reports containing event summaries and investigation recommendations.

## 🧰 Technology Stack

| Technology     | Purpose                                        |
| -------------- | ---------------------------------------------- |
| 🐍 Python      | Core application logic and TCP socket handling |
| 🌐 TCP Sockets | Local decoy service and connection monitoring  |
| 📊 Streamlit   | Interactive dashboard interface                |
| 🐼 Pandas      | Event processing and analysis                  |
| 📈 Plotly      | Interactive charts and visualizations          |
| 🗂️ JSONL      | Structured security event storage              |

## 🏗️ Architecture

```text
🖥️ Test Client
      │
      ▼
🍯 TCP Decoy Service
      │
      ▼
📝 JSONL Event Log
      │
      ▼
📊 Streamlit Dashboard
      │
      ▼
📄 Investigation & Incident Report
```

## ⚙️ Requirements

* Windows 10 or Windows 11
* A compatible Python installation
* Internet access to install dependencies

## 🚀 Installation

**1. Clone the repository**

```cmd
git clone https://github.com/Kurtqttt/Honey-Watch-Security-Monitor.git
cd Honey-Watch-Security-Monitor
```

**2. Create and activate a virtual environment**

```cmd
python -m venv .venv
.venv\Scripts\activate
```

**3. Install dependencies**

```cmd
python -m pip install -r requirements.txt
```

## ▶️ Running HoneyWatch

**Terminal 1 — Start the honeypot**

```cmd
python src\honeypot.py
```

The service listens on `127.0.0.1:2222` and records incoming connections.

**Terminal 2 — Launch the dashboard**

```cmd
.venv\Scripts\activate
python -m streamlit run src\dashboard.py
```

Open the local URL displayed in your terminal, typically:

`http://localhost:8501`

## 🧪 Testing the Lab

With the honeypot running, open another Command Prompt and execute:

```cmd
powershell -NoProfile -Command "$c = New-Object System.Net.Sockets.TcpClient; $c.Connect('127.0.0.1',2222); $s = $c.GetStream(); $r = New-Object System.IO.StreamReader($s); $null = $r.ReadLine(); $r.Dispose(); $c.Dispose()"
```

Then refresh the dashboard and verify that the connection event appears.

Repeat the test several times to observe how the repeated-source review indicator behaves.

## 🔐 Security Considerations & Limitations

* 🔒 **Local-only operation:** The initial listener binds to `127.0.0.1`, restricting access to the local computer.
* 🧪 **Basic decoy service:** This prototype is not a fully emulated SSH server.
* 📌 **Limited telemetry:** It records connection metadata, not authenticated attacker identities or complete attack behavior.
* ⚠️ **Heuristic alerts:** Repeated connections are indicators for investigation, not proof of malicious activity.
* 🌐 **Source attribution:** An IP address does not necessarily identify an individual or the origin of an attack.
* 🛡️ **Safe deployment:** Do not expose the service to external networks without appropriate isolation, access controls, and a security review.

## 🗺️ Future Development

* [ ] Integrate additional decoy services, such as OpenCanary.
* [ ] Add configurable alert thresholds and improved event classification.
* [ ] Implement automated report generation and additional export formats.
* [ ] Add unit tests and configuration validation.
* [ ] Improve dashboard refresh and event deduplication.
* [ ] Include sanitized sample logs, screenshots, and reproducible test results.

## 👨‍💻 About the Project

HoneyWatch was developed as a hands-on cybersecurity learning project to explore:

* Network programming and TCP connection monitoring
* Security event logging and analysis
* SOC-inspired dashboards and alert triage
* Incident documentation and reporting
* Defensive security principles and safe lab practices

## ⚖️ Disclaimer

HoneyWatch is intended for educational purposes and authorized defensive security testing only. Test exclusively on systems and networks you own or have explicit permission to assess.

---

**⭐ HoneyWatch — Observe. Analyze. Investigate.**
