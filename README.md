
# Network Security & Traffic Analysis

## 1. Project Overview
This project is a Python-based network security analysis dashboard. It helps analyze network flow data, threat indicators, investigation cases, and uploaded PCAP files.

## 2. Features
- Network traffic summary
- Threat indicator feed
- Investigation cases
- Protocol and IP analytics
- PCAP file analysis using Scapy
- Threat indicator matching
- Sample data for investigation practice

## 3. Technologies Used
- Python
- Streamlit
- Pandas
- Scapy
- Matplotlib
- Plotly

## 4. Project Structure
```text
Network-Security-Analyzer/
├── data/
├── modules/
├── reports/
├── app.py
├── test_project.py
├── requirements.txt
└── README.md
```

## 5. Installation
Install Python, then run:

```bash
pip install -r requirements.txt
```

## 6. Run the Project
```bash
python -m streamlit run app.py
```

Open the local URL shown in the terminal.

## 7. Testing
Run:

```bash
python test_project.py
```

Expected result:
All project data tests passed!

## 8. PCAP Analysis
Upload a supported PCAP file through the dashboard to inspect packet and protocol information.

## 9. Important Note
Sample IP addresses and indicators are for training and testing. An indicator match is an investigation signal, not proof of malicious activity. PCAP analysis is performed offline on uploaded files.

## 10. Project Purpose
This project demonstrates basic network traffic analysis, indicator matching, and security investigation workflows.

## Project Demo Video

[Watch Project Demonstration](https://drive.google.com/drive/folders/1QnvP1HZTSUfKgmu_5-BbiWJ2mcPL9Jaa)
