
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "events.jsonl"

st.set_page_config(
    page_title="HoneyWatch | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ HoneyWatch Security Monitor")
st.caption("Local honeypot monitoring • Defensive security lab")

@st.cache_data(ttl=3)
def load_events(path, modified_time, file_size):
    records = []
    log_path = Path(path)

    if not log_path.exists():
        return pd.DataFrame()

    with log_path.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                records.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                continue

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)

    required = {
        "timestamp", "source_ip", "destination_port", "event_type"
    }
    if not required.issubset(df.columns):
        return pd.DataFrame()

    df["timestamp"] = pd.to_datetime(
        df["timestamp"], utc=True, errors="coerce"
    )
    df = df.dropna(subset=["timestamp", "source_ip"])
    return df.sort_values("timestamp", ascending=False)


if LOG_FILE.exists():
    stat = LOG_FILE.stat()
    df = load_events(str(LOG_FILE), stat.st_mtime, stat.st_size)
else:
    df = pd.DataFrame()

st.sidebar.header("Dashboard Controls")
period = st.sidebar.selectbox(
    "Time range",
    ["All events", "Last 15 minutes", "Last hour", "Last 24 hours"],
)

if st.sidebar.button("Refresh dashboard"):
    st.cache_data.clear()
    st.rerun()

if df.empty:
    st.info(
        "No valid events found. Start the honeypot and generate a test connection."
    )
    st.stop()

now = pd.Timestamp.now(tz="UTC")

if period != "All events":
    durations = {
        "Last 15 minutes": 15,
        "Last hour": 60,
        "Last 24 hours": 1440,
    }
    cutoff = now - pd.Timedelta(minutes=durations[period])
    df = df[df["timestamp"] >= cutoff].copy()

if df.empty:
    st.warning("No events match this time range.")
    st.stop()

# Classify repeated activity for investigation, not as confirmed attacks.
source_counts = df.groupby("source_ip")["source_ip"].transform("size")
df["severity"] = source_counts.map(
    lambda count: "Medium" if count >= 5 else "Low"
)
df["severity"] = df["severity"].astype(str)

total = len(df)
unique_ips = df["source_ip"].nunique()
ports = df["destination_port"].nunique()
medium_events = int((df["severity"] == "Medium").sum())

a, b, c, d = st.columns(4)
a.metric("Connection Events", total)
b.metric("Unique Source IPs", unique_ips)
c.metric("Destination Ports", ports)
d.metric("Events from Repeated Sources", medium_events)

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Connection Timeline")
    timeline = (
        df.set_index("timestamp")
        .resample("1min")
        .size()
        .reset_index(name="Events")
    )
    fig = px.line(
        timeline,
        x="timestamp",
        y="Events",
        markers=True,
        title="Events per Minute",
    )
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Top Source IPs")
    top_sources = (
        df.groupby("source_ip")
        .size()
        .reset_index(name="Events")
        .sort_values("Events", ascending=False)
        .head(10)
    )
    fig = px.bar(
        top_sources,
        x="source_ip",
        y="Events",
        title="Top 10 Sources",
    )
    st.plotly_chart(fig, use_container_width=True)

st.subheader("Investigation Alerts")

alerts = (
    df.groupby("source_ip")
    .size()
    .reset_index(name="Connections")
)
alerts = alerts[alerts["Connections"] >= 5]

if alerts.empty:
    st.success("No source reached the 5-event review threshold.")
else:
    st.warning(
        f"{len(alerts)} source IP(s) reached the review threshold. "
        "Repeated connections alone do not prove malicious activity."
    )
    st.dataframe(alerts, use_container_width=True, hide_index=True)

st.subheader("Security Event Explorer")

search = st.text_input("Search source IP")
severity_filter = st.multiselect(
    "Severity",
    options=["Low", "Medium"],
    default=["Low", "Medium"],
)

filtered = df[df["severity"].isin(severity_filter)].copy()

if search.strip():
    filtered = filtered[
        filtered["source_ip"].astype(str).str.contains(
            search.strip(), case=False, regex=False
        )
    ]

display = filtered.copy()
display["timestamp"] = display["timestamp"].dt.strftime(
    "%Y-%m-%d %H:%M:%S UTC"
)

columns = [
    "timestamp", "source_ip", "source_port",
    "destination_port", "event_type", "severity"
]
columns = [column for column in columns if column in display.columns]

st.dataframe(
    display[columns],
    use_container_width=True,
    hide_index=True,
)

csv_data = display[columns].to_csv(index=False).encode("utf-8")
st.download_button(
    "Download filtered events (CSV)",
    data=csv_data,
    file_name="honeywatch_events.csv",
    mime="text/csv",
)


st.divider()
st.subheader("Incident Report Generator")

st.write(
    "Generate a text report from the events in the selected time range."
)

if st.button("Generate incident report"):
    report_time = pd.Timestamp.now(tz="UTC")
    first_event = df["timestamp"].min()
    last_event = df["timestamp"].max()

    source_summary = (
        df.groupby("source_ip")
        .size()
        .sort_values(ascending=False)
        .head(10)
    )

    repeated_sources = source_summary[source_summary >= 5]

    report_lines = [
        "HONEYWATCH SECURITY INCIDENT REPORT",
        "=" * 40,
        f"Generated: {report_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Selected range: {period}",
        f"First observed event: {first_event}",
        f"Last observed event: {last_event}",
        "",
        "SUMMARY",
        "-" * 40,
        f"Total connection events: {len(df)}",
        f"Unique source IPs: {df['source_ip'].nunique()}",
        f"Destination ports observed: "
        f"{df['destination_port'].nunique()}",
        f"Events from repeated sources: {medium_events}",
        "",
        "TOP SOURCE IP ADDRESSES",
        "-" * 40,
    ]

    for ip, count in source_summary.items():
        report_lines.append(f"{ip}: {count} event(s)")

    report_lines.extend([
        "",
        "REPEATED-SOURCE OBSERVATIONS",
        "-" * 40,
    ])

    if repeated_sources.empty:
        report_lines.append(
            "No source reached the 5-event review threshold."
        )
    else:
        for ip, count in repeated_sources.items():
            report_lines.append(
                f"Review {ip}: {count} event(s) observed."
            )

    report_lines.extend([
        "",
        "RECOMMENDED INVESTIGATION",
        "-" * 40,
        "1. Review event timestamps and connection patterns.",
        "2. Verify whether the source is expected or authorized.",
        "3. Correlate events with other available security logs.",
        "4. Preserve relevant evidence before making changes.",
        "5. Escalate confirmed suspicious activity according to policy.",
        "",
        "LIMITATIONS",
        "-" * 40,
        "This report summarizes honeypot connection events only.",
        "Repeated connections are not proof of malicious activity.",
        "Source IPs may represent shared systems or intermediaries.",
        "This report does not establish attacker identity or intent.",
    ])

    report_text = "\n".join(report_lines) + "\n"

    st.success("Incident report generated.")
    st.download_button(
        "Download incident report (.txt)",
        data=report_text,
        file_name="honeywatch_incident_report.txt",
        mime="text/plain",
        key="download_incident_report",
    )

st.sidebar.divider()
st.sidebar.caption(f"Log file: {LOG_FILE}")
st.caption(
    "Severity is a simple source-frequency heuristic. "
    "It is not a validated threat score, and source IPs may be shared or spoofed."
)