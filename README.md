🛡️ SentinelAI: Log Analysis & Network Security Dashboard
SentinelAI is an intelligent, unified security monitoring dashboard built with Streamlit. It bridges the gap between proactive network auditing and reactive log forensics, providing security analysts and students with an accessible, interactive platform to hunt for threats and map attack surfaces.

🚀 Key Features
Machine Learning Log Forensics: Automatically ingests Windows Security Logs (CSV format), converts categorical text features into numeric encodings on the fly, and uses an Isolation Forest unsupervised anomaly detection model to isolate and flag suspicious event lines.

Universal Network Scanner: Direct integration with Nmap (python-nmap), allowing multi-tier active scanning directly from the UI. It supports four scan depths:

Standard Scan (-F fast port discovery)

Comprehensive Scan (-sV service version detection)

All Ports (-p- comprehensive 1-65535 sweep)

Aggressive Scan (-A OS fingerprinting, script scanning, and traceroute)

Dynamic Security Metrics & Visualizations: Computes live metrics for active hosts, open ports, and detected services. Generates interactive data visualizations (using Plotly Express), including anomaly histograms and service distribution pie charts.

Cross-Platform Path Resolver: Features an automated helper utility to dynamically locate local Nmap binaries across both Windows (standard Program Files directories) and Linux (/usr/bin environments).

🛠️ Tech Stack
Frontend/UI: Streamlit

Data Science & Machine Learning: Scikit-learn (Isolation Forest), Pandas, NumPy

Visualization: Plotly Express

Network Security: Nmap Engine (python-nmap wrapper)

Quick Start
Ensure Nmap is installed on your local system (nmap.org).

Install the requirements: pip install streamlit pandas plotly scikit-learn python-nmap

Run the app: streamlit run app.py
