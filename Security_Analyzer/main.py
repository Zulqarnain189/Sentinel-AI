import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np
import nmap
import os
from sklearn.ensemble import IsolationForest

# ---------------- CONFIG ----------------
st.set_page_config(page_title="SentinelAI: Log and Network Monitoring", layout="wide")
st.title("🛡️ SentinelAI: Log and Network Monitoring")

# ---------------- HELPERS ----------------
def get_nmap_path():
    possible_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap"
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return None

# ---------------- SIDEBAR ----------------
st.sidebar.header("Controls")
uploaded_file = st.sidebar.file_uploader("Upload Windows Security Logs (CSV)", type=["csv"])

# ---------------- LOG ANALYSIS ----------------
if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.sidebar.success("Log File Loaded!")
    if len(df) > 5:
        df_numeric = df.select_dtypes(include=[np.number])
        if df_numeric.shape[1] < 2:
            st.warning("Processing text logs into numeric features...")
            for col in df.columns:
                if df[col].dtype == 'object':
                    df[f'{col}_code'] = df[col].astype('category').cat.codes
            df_numeric = df.select_dtypes(include=[np.number])
            
        if st.sidebar.button("Analyze Logs"):
            model = IsolationForest(contamination=0.05, random_state=42)
            df['anomaly'] = model.fit_predict(df_numeric)
            df['Result'] = df['anomaly'].map({1: 'Safe', -1: 'Suspicious'})
            st.subheader("📊 Log Analysis Results")
            fig = px.histogram(df, x="Result", color="Result", color_discrete_map={"Safe": "green", "Suspicious": "red"})
            st.plotly_chart(fig)
            st.write("⚠️ Suspicious Log Events:")
            st.dataframe(df[df['Result'] == 'Suspicious'], use_container_width=True)
    else:
        st.error("The file contains too little data!!")
else:
    st.info("Upload Windows Security Logs (CSV) to begin.")

# ---------------- UNIVERSAL NMAP SCANNER ----------------
st.sidebar.markdown("---")
st.sidebar.subheader("🌐 Universal Network Scanner")
scan_ip = st.sidebar.text_input("Enter Target IP / Range", placeholder="e.g. 192.168.1.1 or 192.168.1.0/24")

scan_type = st.sidebar.selectbox(
    "Select Scan Depth",
    ["Standard Scan (Fast)", "Comprehensive Scan", "All Ports (1-65535)", "Aggressive (OS & Version)"]
)

if st.sidebar.button("🚀 Start Scanning"):
    if not scan_ip:
        st.error("Target IP enter karna zaroori hai!")
    else:
        nmap_exe = get_nmap_path()
        if not nmap_exe:
            st.error("Nmap system par nahi mila. Download: nmap.org")
        else:
            try:
                with st.spinner(f"Scanning target: {scan_ip}..."):
                    nm = nmap.PortScanner(nmap_search_path=(nmap_exe,))
                    if scan_type == "Standard Scan (Fast)":
                        args = "-T4 -F -Pn"
                    elif scan_type == "Comprehensive Scan":
                        args = "-T4 -sV -Pn"
                    elif scan_type == "All Ports (1-65535)":
                        args = "-p- -T4 -Pn"
                    else:
                        args = "-A -T4 -Pn"
                    
                    nm.scan(hosts=scan_ip, arguments=args)
                    data = []
                    for host in nm.all_hosts():
                        host_state = nm[host].state()
                        hostname = nm[host].hostname() if nm[host].hostname() else "Unknown"
                        for proto in nm[host].all_protocols():
                            lport = nm[host][proto].keys()
                            for port in lport:
                                service = nm[host][proto][port]
                                data.append({
                                    "Host": host,
                                    "Hostname": hostname,
                                    "Status": host_state,
                                    "Protocol": proto,
                                    "Port": port,
                                    "Service": service.get('name', 'unknown'),
                                    "Version": service.get('product', '') + " " + service.get('version', ''),
                                    "State": service.get('state', 'unknown')
                                })
                    
                    df_scan = pd.DataFrame(data)
                    if not df_scan.empty:
                        st.subheader(f"📡 Scan Results for {scan_ip}")
                        m1, m2, m3 = st.columns(3)
                        m1.metric("Active Hosts", df_scan["Host"].nunique())
                        m2.metric("Open Ports Found", len(df_scan[df_scan["State"] == "open"]))
                        m3.metric("Services Detected", df_scan["Service"].nunique())
                        st.dataframe(df_scan, use_container_width=True)
                        st.subheader("📊 Port & Service Overview")
                        # FIXED LINE BELOW
                        fig = px.pie(df_scan, names='Service', title='Services Distribution')
                        st.plotly_chart(fig)
                    else:
                        st.warning("No results. Ensure IP is correct.")
            except Exception as e:
                st.error(f"Scan failed: {e}")