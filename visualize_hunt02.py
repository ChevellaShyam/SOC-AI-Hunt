import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("execution_logs.csv")
df["timestamp"] = pd.to_datetime(df["timestamp"])

# 1. Anomaly score by process
plt.figure(figsize=(10, 6))
plt.bar(df["process"], df["anomaly_score"])
plt.xticks(rotation=45, ha="right")
plt.ylabel("Anomaly Score")
plt.title("Hunt #2 — Execution Anomaly Scores")
plt.tight_layout()
plt.savefig("hunt02_execution_scores.png")
plt.close()

# 2. Execution timeline
plt.figure(figsize=(12, 6))
plt.plot(df["timestamp"], df["anomaly_score"], marker="o")
plt.xticks(rotation=45)
plt.ylabel("Anomaly Score")
plt.xlabel("Timestamp")
plt.title("Hunt #2 — Suspicious Execution Timeline")
plt.tight_layout()
plt.savefig("hunt02_execution_timeline.png")
plt.close()

# 3. Persistence / execution type
counts = df["execution_type"].value_counts()

plt.figure(figsize=(8, 6))
plt.bar(counts.index, counts.values)
plt.ylabel("Count")
plt.title("Hunt #2 — Execution Type Distribution")
plt.xticks(rotation=30, ha="right")
plt.tight_layout()
plt.savefig("hunt02_execution_types.png")
plt.close()

print("=" * 70)
print("HUNT #2 VISUALIZATION COMPLETE")
print("=" * 70)
print()
print("Created:")
print("hunt02_execution_scores.png")
print("hunt02_execution_timeline.png")
print("hunt02_execution_types.png")