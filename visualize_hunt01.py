import pandas as pd
import matplotlib.pyplot as plt


# ============================================================
# LOAD DATA
# ============================================================

df = pd.read_csv("authentication_logs.csv")

df["timestamp"] = pd.to_datetime(df["timestamp"])
df["hour"] = df["timestamp"].dt.hour


# ============================================================
# CREATE OUTPUT DIRECTORY
# ============================================================

import os

os.makedirs("hunt01_results", exist_ok=True)


# ============================================================
# CHART 1 — AUTHENTICATIONS BY HOUR
# ============================================================

hour_counts = df["hour"].value_counts().sort_index()

plt.figure(figsize=(10, 5))

plt.bar(
    hour_counts.index,
    hour_counts.values
)

plt.title("Authentication Activity by Hour")
plt.xlabel("Hour of Day")
plt.ylabel("Authentication Events")

plt.xticks(range(24))

plt.tight_layout()

plt.savefig(
    "hunt01_results/authentication_by_hour.png",
    dpi=150
)

plt.close()


# ============================================================
# CHART 2 — AUTHENTICATIONS BY SOURCE IP
# ============================================================

ip_counts = df["src_ip"].value_counts()

plt.figure(figsize=(10, 5))

plt.bar(
    ip_counts.index,
    ip_counts.values
)

plt.title("Authentication Events by Source IP")
plt.xlabel("Source IP")
plt.ylabel("Authentication Events")

plt.xticks(rotation=30)

plt.tight_layout()

plt.savefig(
    "hunt01_results/authentication_by_ip.png",
    dpi=150
)

plt.close()


# ============================================================
# CHART 3 — ALICE TIMELINE
# ============================================================

alice = df[
    df["user"] == "alice"
].sort_values("timestamp")


plt.figure(figsize=(12, 5))

plt.scatter(
    alice["timestamp"],
    alice["dest_computer"]
)

plt.title("Alice Authentication Timeline")
plt.xlabel("Timestamp")
plt.ylabel("Destination Computer")

plt.xticks(rotation=45)

plt.tight_layout()

plt.savefig(
    "hunt01_results/alice_authentication_timeline.png",
    dpi=150
)

plt.close()


# ============================================================
# SUMMARY
# ============================================================

print("=" * 70)
print("HUNT #1 VISUALIZATION COMPLETE")
print("=" * 70)

print("\nCreated:")

print(
    "hunt01_results/authentication_by_hour.png"
)

print(
    "hunt01_results/authentication_by_ip.png"
)

print(
    "hunt01_results/alice_authentication_timeline.png"
)