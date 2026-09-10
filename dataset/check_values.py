# check_actual_values.py
import pandas as pd

# Load a sample
train = pd.read_csv("guide_train.csv", nrows=100)

# Check IpAddress column
print("=== IP ADDRESS VALUES ===")
print(train['IpAddress'].head(10))
print(f"Unique IP values: {train['IpAddress'].nunique()}")

# Check what the values look like
print("\n=== SAMPLE IP ENTRIES ===")
for i, val in enumerate(train['IpAddress'].head(5)):
    print(f"  Row {i}: {val} (type: {type(val)})")

# Check if any are actual IPs
is_ip = train['IpAddress'].astype(str).str.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
has_ips = is_ip.any()
print(f"\nHas actual IPs? {has_ips}")

# Count by IncidentGrade
print("\n=== INCIDENT GRADE DISTRIBUTION ===")
print(train['IncidentGrade'].value_counts())