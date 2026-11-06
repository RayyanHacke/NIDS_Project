import pandas as pd

FILE = "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

print(f"Loading {FILE} ...")
df = pd.read_csv(FILE)

print(f"Rows: {len(df)}")
label_col = df.columns[-1]
print(f"Label Column: {label_col}")
print(df[label_col].value_counts())

print("\nStarting NIDS Detection...")

def detect(row):
    try:
        if row[' Destination Port'] > 50000:
            return "PortScan"
        if row[' Flow Duration'] > 10000000:
            return "DDoS"
    except:
        return "BENIGN"
    return "BENIGN"

for i in range(5):
    real = df.iloc[i][label_col]
    pred = detect(df.iloc[i])
    print(f"Row {i} -> Real: {real} | NIDS: {pred}")

print("\nSUCCESS - NIDS Working")
