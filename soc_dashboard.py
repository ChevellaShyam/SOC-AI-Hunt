import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(
    page_title="SOC-AI-Hunt",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SOC-AI-HUNT")
st.subheader("AI-Assisted Threat Hunting & Incident Investigation")

# Load data
auth = pd.read_csv("hunt01_results/scored_authentication_logs.csv")
persistence = pd.read_csv("persistence_scored.csv")
process = pd.read_csv("process_execution_logs.csv")

auth["timestamp"] = pd.to_datetime(auth["timestamp"])
persistence["timestamp"] = pd.to_datetime(persistence["timestamp"])
process["timestamp"] = pd.to_datetime(process["timestamp"])

# Metrics
high_auth = len(auth[auth["anomaly_score"] >= 70])
high_persistence = len(persistence[persistence["anomaly_score"] >= 70])
high_process = len(process[process["anomaly_score"] >= 70])

st.markdown("## 🚨 Incident Overview")

c1, c2, c3, c4 = st.columns(4)

c1.metric("Auth High-Risk Events", high_auth)
c2.metric("Persistence High-Risk", high_persistence)
c3.metric("Process High-Risk", high_process)
c4.metric("Incident Severity", "HIGH")

st.divider()

# Attack chain
st.markdown("## 🔗 Detected Attack Chain")

st.info(
    """
    Rare IP Authentication → Multi-System Access → DC01 Access
    → Persistence on WS07 → Suspicious PowerShell
    → Encoded/Hidden Execution
    """
)

# Timeline
st.markdown("## ⏱️ Attack Timeline")

alice_auth = auth[
    (auth["user"] == "alice") &
    (auth["anomaly_score"] >= 70)
][
    ["timestamp", "dest_computer", "src_ip", "anomaly_score"]
].copy()

alice_auth["event"] = "Authentication → " + alice_auth["dest_computer"]

p_events = persistence[
    persistence["user"] == "alice"
][
    ["timestamp", "host", "mechanism", "name", "anomaly_score"]
].copy()

p_events["event"] = (
    "Persistence → "
    + p_events["mechanism"]
    + " (" + p_events["name"] + ")"
)

e_events = process[
    process["user"] == "alice"
][
    ["timestamp", "host", "process", "anomaly_score"]
].copy()

e_events["event"] = "Execution → " + e_events["process"]

timeline = pd.concat([
    alice_auth[["timestamp", "event", "anomaly_score"]],
    p_events[["timestamp", "event", "anomaly_score"]],
    e_events[["timestamp", "event", "anomaly_score"]]
])

timeline = timeline.sort_values("timestamp")

fig = px.scatter(
    timeline,
    x="timestamp",
    y="event",
    size="anomaly_score",
    color="anomaly_score",
    hover_data=["timestamp", "event", "anomaly_score"],
    title="Correlated Attack Timeline"
)

st.plotly_chart(fig, use_container_width=True)

# Authentication section
st.markdown("## 🔑 Hunt #1 — Authentication")

col1, col2 = st.columns(2)

with col1:
    st.write("### High-Risk Authentication")

    st.dataframe(
        alice_auth.sort_values("timestamp"),
        use_container_width=True,
        hide_index=True
    )

with col2:
    fig = px.bar(
        alice_auth["dest_computer"].value_counts(),
        title="Alice — Systems Accessed"
    )

    st.plotly_chart(fig, use_container_width=True)

# Persistence
st.markdown("## 🧬 Hunt #2 — Persistence")

st.dataframe(
    persistence[persistence["anomaly_score"] >= 70][
        [
            "timestamp",
            "host",
            "user",
            "mechanism",
            "name",
            "anomaly_score",
            "risk_level"
        ]
    ].sort_values("timestamp"),
    use_container_width=True,
    hide_index=True
)

# Process
st.markdown("## ⚙️ Hunt #3 — Process Execution")

st.dataframe(
    process[process["anomaly_score"] >= 70][
        [
            "timestamp",
            "host",
            "user",
            "process",
            "command",
            "parent_process",
            "anomaly_score",
            "risk_level"
        ]
    ].sort_values("timestamp"),
    use_container_width=True,
    hide_index=True
)

# MITRE
st.markdown("## 🎯 MITRE ATT&CK Mapping")

mitre = pd.DataFrame({
    "Technique": [
        "T1078",
        "T1053.005",
        "T1547.001",
        "T1543.003",
        "T1059.001",
        "T1027",
        "T1564.001",
        "T1036"
    ],
    "Technique Name": [
        "Valid Accounts",
        "Scheduled Task/Job",
        "Registry Run Keys / Startup Folder",
        "Windows Service",
        "PowerShell",
        "Obfuscated/Compressed Files",
        "Hidden Window",
        "Masquerading"
    ]
})

st.dataframe(
    mitre,
    use_container_width=True,
    hide_index=True
)

# Final verdict
st.markdown("## 🚨 Final Assessment")

st.error(
    """
    HIGH-CONFIDENCE SUSPICIOUS ATTACK CHAIN

    Authentication + Persistence + Process Execution are correlated
    around the same user and host context.

    Status: ESCALATE FOR FULL INCIDENT RESPONSE
    """
)

st.caption(
    "SOC-AI-Hunt — AI-assisted threat hunting laboratory"
)