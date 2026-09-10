# inspect_guide.py
import pandas as pd

# Check train data
print("=== TRAIN DATA ===")
train = pd.read_csv("guide_train.csv", nrows=1000)
print(f"Columns: {list(train.columns)}")
print(f"Shape: {train.shape}")
print("\nSample row:")
print(train.iloc[0].to_dict())

print("\n" + "="*60)

# Check test data
print("=== TEST DATA ===")
test = pd.read_csv("guide_test.csv", nrows=1000)
print(f"Columns: {list(test.columns)}")
print(f"Shape: {test.shape}")
print("\nSample row:")
print(test.iloc[0].to_dict())

# Check if we have the evidence fields we need
evidence_fields = ['IpAddress', 'Url', 'Sha256', 'AccountName', 'DeviceName']
found = [f for f in evidence_fields if f in train.columns]
missing = [f for f in evidence_fields if f not in train.columns]

print("\n" + "="*60)
print("EVIDENCE FIELDS FOUND:", found)
print("EVIDENCE FIELDS MISSING:", missing)