import pandas as pd
import random
from datetime import datetime, timedelta

random.seed(42)

users = [
    "alice",
    "bob",
    "charlie",
    "david",
    "admin"
]

computers = [
    "DC01",
    "FILE01",
    "WEB01",
    "SQL01",
    "APP01"
]

normal_ips = [
    "10.10.10.10",
    "10.10.10.11",
    "10.10.10.12",
    "10.10.10.13"
]

events = []

start_time = datetime(2026, 8, 25, 8, 0, 0)

# --------------------------------------------------
# NORMAL AUTHENTICATION ACTIVITY
# --------------------------------------------------

for i in range(1500):

    user = random.choice(users)

    # Normal users mostly use known internal IPs
    src_ip = random.choice(normal_ips)

    computer = random.choice(computers)

    # Mostly business hours
    hour = random.randint(8, 18)

    timestamp = start_time + timedelta(
        days=random.randint(0, 6),
        hours=hour - 8,
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59)
    )

    logon_type = random.choice([2, 3, 3, 3, 10])

    events.append({
        "timestamp": timestamp,
        "user": user,
        "src_ip": src_ip,
        "dest_computer": computer,
        "logon_type": logon_type
    })


# --------------------------------------------------
# SUSPICIOUS ACTIVITY
# --------------------------------------------------

# Alice suddenly accesses multiple systems
# from a new IP during the night.

suspicious_ip = "10.10.20.15"

attack_time = datetime(2026, 8, 28, 2, 13, 0)

for i, computer in enumerate(computers):

    timestamp = attack_time + timedelta(
        seconds=i * 20
    )

    events.append({
        "timestamp": timestamp,
        "user": "alice",
        "src_ip": suspicious_ip,
        "dest_computer": computer,
        "logon_type": 3
    })


# Additional suspicious failed attempts

for i in range(15):

    timestamp = attack_time - timedelta(
        minutes=random.randint(1, 10)
    )

    events.append({
        "timestamp": timestamp,
        "user": "alice",
        "src_ip": suspicious_ip,
        "dest_computer": random.choice(computers),
        "logon_type": 3
    })


# --------------------------------------------------
# CREATE DATAFRAME
# --------------------------------------------------

df = pd.DataFrame(events)

df = df.sort_values("timestamp")

df.to_csv(
    "authentication_logs.csv",
    index=False
)

print("Dataset created successfully!")
print(f"Total events: {len(df)}")
print(f"Users: {df['user'].nunique()}")
print(f"Source IPs: {df['src_ip'].nunique()}")
print()
print(df.head(10))