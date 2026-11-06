# NIDS_Project - Network Intrusion Detection System
Live NIDS using Machine Learning

# 🛡️ NIDS_Project - Network Intrusion Detection System

Live Network Intrusion Detection System using Machine Learning.

**Author:** RayyanHacke
**YouTube:** https://youtube.com/@silladon29

---

### ✨ Features
- Live Packet Sniffing (Scapy)
- ML Attack Detection - DDoS, PortScan, WebAttack
- Real-time Alerts
- Works on Kali, Linux & Termux

### 📁 Files
- `live_nids.py` - Main Live Tool
- `nids_final.py` - Final ML Version
- `final_project.py` - Training + Detection

---

### 🐉 1. Installation For Kali Linux / Linux

```bash
# Update
sudo apt update && sudo apt upgrade -y

# Clone Tool
git clone https://github.com/RayyanHacke/NIDS_Project.git
cd NIDS_Project/MachineLearningCVE

# Install Python Requirements
pip3 install scapy pandas scikit-learn numpy

# Run Tool (Root Required)
sudo python3 live_nids.py

#check logs
cat nids_live_alerts.log

# Update Termux
pkg update && pkg upgrade -y
pkg install python git -y

# Clone Tool
git clone https://github.com/RayyanHacke/NIDS_Project.git
cd NIDS_Project/MachineLearningCVE

# Install Requirements
pip install scapy pandas scikit-learn numpy

# Run Tool
python live_nids.py

#Train my tool
python final_project.py

#requirements.txt
scapy
pandas
scikit-learn
numpy


