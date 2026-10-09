\# HoneyWatch — Honeypot Security Monitoring Dashboard



HoneyWatch is a beginner-friendly cybersecurity portfolio project built with Python. It records connection attempts against a local TCP decoy service and presents the resulting events through an interactive security monitoring dashboard.



\## Features



\* \*\*TCP Honeypot:\*\* Records incoming local test connections.

\* \*\*JSONL Logging:\*\* Stores events with timestamps, source addresses, and destination ports.

\* \*\*Security Dashboard:\*\* Visualizes connection activity, source IPs, and event statistics.

\* \*\*Repeated-Source Alerts:\*\* Flags sources that reach a configurable event-count threshold.

\* \*\*Event Filtering:\*\* Filter records by time range, source IP, and severity.

\* \*\*CSV Export:\*\* Export filtered events for further analysis.

\* \*\*Incident Reports:\*\* Generate downloadable text reports with observations and investigation recommendations.



\## Technology Stack



\* Python

\* TCP sockets

\* Streamlit

\* Pandas

\* Plotly

\* JSON Lines



\## Architecture



Test Client → TCP Decoy → JSONL Event Log → Streamlit Dashboard → Investigation Report



\## Requirements



\* Windows 10 or Windows 11

\* A compatible Python installation

\* Internet access for installing dependencies



\## Installation



Clone or download this repository, then open Command Prompt in the project directory.



Create a virtual environment:



```cmd

python -m venv .venv

.venv\\Scripts\\activate

```



Install the dependencies:



```cmd

python -m pip install -r requirements.txt

```



\## Running HoneyWatch



Start the honeypot in the first terminal:



```cmd

python src\\honeypot.py

```



Start the dashboard in a second terminal:



```cmd

.venv\\Scripts\\activate

python -m streamlit run src\\dashboard.py

```



Open the local URL displayed by Streamlit, typically `http://localhost:8501`.



\## Testing



The initial lab uses a loopback address (`127.0.0.1`) and TCP port `2222`.



To generate a test connection, run this command in a separate Command Prompt:



```cmd

powershell -NoProfile -Command "$c = New-Object System.Net.Sockets.TcpClient; $c.Connect('127.0.0.1',2222); $s = $c.GetStream(); $r = New-Object System.IO.StreamReader($s); $null = $r.ReadLine(); $r.Dispose(); $c.Dispose()"

```



Refresh the dashboard and verify that the event count increases.



\## Security and Limitations



\* The initial listener is restricted to the local computer.

\* This is a basic TCP decoy, not a fully emulated SSH server.

\* The prototype records connection attempts, not authenticated attacker identities.

\* Repeated connections are investigation indicators, not proof of malicious activity.

\* Source addresses can represent shared systems, proxies, or other intermediaries.

\* Do not expose the service to external networks without appropriate isolation, access controls, and additional security review.



\## Future Improvements



\* Integrate OpenCanary for additional decoy services.

\* Add structured severity rules and configurable alert thresholds.

\* Add automated report generation and additional log formats.

\* Add unit tests and configuration validation.

\* Improve dashboard refresh and event deduplication.

\* Add screenshots, sample sanitized logs, and reproducible test results.



\## Author



Developed as a hands-on cybersecurity learning project to explore network monitoring, security event analysis, Python development, and incident reporting.



\## Disclaimer



HoneyWatch is intended for authorized defensive security testing and education. Test only systems and networks you own or have explicit permission to assess.



