import pandas as pd
from ai_hunt_agent import ThreatHuntAgent


# Load logs
df = pd.read_csv("authentication_logs.csv")

df["timestamp"] = pd.to_datetime(df["timestamp"])

# Create hour field
df["hour"] = df["timestamp"].dt.hour


# Identify off-hours activity
off_hours = df[
    (df["hour"] < 7) |
    (df["hour"] > 20)
]


# Identify uncommon IPs
ip_frequency = df["src_ip"].value_counts()

rare_ips = ip_frequency[
    ip_frequency < 50
].index


# Combine signals
interesting = df[
    (
        (df["hour"] < 7) |
        (df["hour"] > 20)
    )
    &
    (
        df["src_ip"].isin(rare_ips)
    )
]


# Convert evidence to text
evidence = interesting[
    [
        "timestamp",
        "user",
        "src_ip",
        "dest_computer",
        "logon_type"
    ]
].to_string(index=False)


# Create AI agent
agent = ThreatHuntAgent()


# Ask AI to investigate
question = """
You are investigating Hunt #1: possible credential abuse.

Analyze the authentication evidence below.

Determine:

1. What facts are directly supported by the logs?
2. What behavior is anomalous compared with the apparent baseline?
3. What benign explanations are possible?
4. What malicious explanations are possible?
5. Which MITRE ATT&CK techniques might be relevant?
6. What additional evidence should a human analyst collect?
7. Give a HIGH, MEDIUM, or LOW confidence assessment.

Do NOT claim that an attack is confirmed.
Separate evidence from hypotheses.

"""

result = agent.analyze(
    question,
    data_context=evidence
)


print("\n" + "=" * 70)
print("AI-ASSISTED HUNT #1 INVESTIGATION")
print("=" * 70)

print(result)