import streamlit as st
import pandas as pd
from pathlib import Path

st.set_page_config(
    page_title="Network Security Analyzer",
    page_icon="🛡️",
    layout="wide"
)

DATA_DIR = Path(__file__).parent / "data"

st.title("🛡️ Network Security & Traffic Analyzer")
st.write("Analyze network traffic and identify matching threat indicators.")

@st.cache_data
def load_csv(filename):
    path = DATA_DIR / filename
    if path.exists():
        return pd.read_csv(path)
    return pd.DataFrame()

flows = load_csv("flow_summary.csv")
indicators = load_csv("indicator_feed.csv")
cases = load_csv("indicator_investigation_cases.csv")

st.header("1. Network Traffic Summary")

if not flows.empty:
    col1, col2 = st.columns(2)
    col1.metric("Total Connections", len(flows))
    col2.metric("Total Columns", len(flows.columns))

    st.dataframe(flows, use_container_width=True)

    # Find indicator values that also appear in traffic data
    indicator_values = set(
        indicators.astype(str).values.flatten()
    ) if not indicators.empty else set()

    matched_rows = flows[
        flows.astype(str).apply(
            lambda row: any(value in indicator_values
                            for value in row),
            axis=1
        )
    ]

    st.subheader("2. Indicator Matches")

    if not matched_rows.empty:
        st.warning(f"{len(matched_rows)} matching connection(s) found.")
        st.dataframe(matched_rows, use_container_width=True)
    else:
        st.success("No matching indicators found.")
else:
    st.error("flow_summary.csv not found in the data folder.")

st.header("3. Threat Indicator Feed")
if not indicators.empty:
    st.dataframe(indicators, use_container_width=True)
else:
    st.info("Indicator feed not found.")

st.header("4. Investigation Cases")
if not cases.empty:
    st.dataframe(cases, use_container_width=True)
else:
    st.info("Investigation cases not found.")

st.caption("Training tool: indicator matches require analyst investigation.")

st.header("5. Traffic Analytics")

if not flows.empty:
    # Protocol chart
    if "protocol" in flows.columns:
        st.subheader("Protocol Distribution")
        protocol_counts = flows["protocol"].value_counts()
        st.bar_chart(protocol_counts)

    # Source IP chart
    if "src_ip" in flows.columns:
        st.subheader("Top Source IP Addresses")
        source_counts = flows["src_ip"].value_counts().head(10)
        st.bar_chart(source_counts)

    # Destination port chart
    if "dst_port" in flows.columns:
        st.subheader("Destination Port Distribution")
        port_counts = flows["dst_port"].astype(str).value_counts().head(10)
        st.bar_chart(port_counts)

else:
    st.info("No traffic data available for charts.")

    # 6. PCAP File Analysis
st.header("6. PCAP File Analysis")

from scapy.all import rdpcap, IP, TCP, UDP
from collections import Counter

uploaded_file = st.file_uploader(
    "Upload a PCAP file",
    
)

if uploaded_file is not None:
    try:
        packets = rdpcap(uploaded_file)

        st.success(f"Successfully loaded {len(packets)} packets!")

        protocols = Counter()
        source_ips = Counter()
        destination_ips = Counter()
        ports = Counter()

        for packet in packets:
            if IP in packet:
                source_ips[packet[IP].src] += 1
                destination_ips[packet[IP].dst] += 1

                if TCP in packet:
                    protocols["TCP"] += 1
                    ports[packet[TCP].dport] += 1
                elif UDP in packet:
                    protocols["UDP"] += 1
                    ports[packet[UDP].dport] += 1
                else:
                    protocols["Other IP"] += 1

        st.subheader("Protocol Distribution")
        st.bar_chart(dict(protocols))

        st.subheader("Top Source IPs")
        st.bar_chart(dict(source_ips.most_common(10)))

        st.subheader("Top Destination IPs")
        st.bar_chart(dict(destination_ips.most_common(10)))

        st.subheader("Destination Ports")
        st.bar_chart(dict(ports.most_common(10)))

    except Exception as e:
        st.error(f"Error reading PCAP file: {e}")

        




# 7. Threat Indicator Matching

st.header("7. Threat Indicator Matching")

if not flows.empty and not indicators.empty:

    import ipaddress

    # Collect IP addresses from network flows
    flow_ips = []

    for _, flow in flows.iterrows():
        for column in ["src_ip", "dst_ip"]:
            ip = str(flow[column]).strip()

            if ip and ip.lower() != "nan":
                flow_ips.append({
                    "flow_id": flow["flow_id"],
                    "ip_address": ip,
                    "direction": column
                })

    # Match flow IPs against indicator feed
    matches = []

    for item in flow_ips:
        for _, indicator in indicators.iterrows():

            indicator_value = str(indicator["indicator"]).strip()

            try:
                ipaddress.ip_address(indicator_value)
            except ValueError:
                continue

            if item["ip_address"] == indicator_value:
                matches.append({
                    "Flow ID": item["flow_id"],
                    "Matched IP": item["ip_address"],
                    "Traffic Direction": item["direction"],
                    "Indicator Type": indicator["indicator_type"],
                    "Confidence": indicator["source_confidence"],
                    "Label": indicator["fixture_label"],
                    "Analyst Comment": indicator["analyst_comment"]
                })

    if matches:
        st.warning(f"Found {len(matches)} indicator matches!")

        st.dataframe(
            pd.DataFrame(matches),
            width="stretch"
        )
    else:
        st.success("No matching IP indicators found.")

else:
    st.info("Flow data or indicator data is missing.")


# 8. Download Reports

st.header("8. Download Reports")

if not flows.empty:
    st.download_button(
        label="Download Network Traffic Report",
        data=flows.to_csv(index=False).encode("utf-8"),
        file_name="network_traffic_report.csv",
        mime="text/csv"
    )

if not indicators.empty:
    st.download_button(
        label="Download Threat Indicator Report",
        data=indicators.to_csv(index=False).encode("utf-8"),
        file_name="threat_indicator_report.csv",
        mime="text/csv"
    )

if not cases.empty:
    st.download_button(
        label="Download Investigation Cases",
        data=cases.to_csv(index=False).encode("utf-8"),
        file_name="investigation_cases_report.csv",
        mime="text/csv"
    )

if "matches" in locals() and matches:
    matches_df = pd.DataFrame(matches)

    st.download_button(
        label="Download Indicator Matching Report",
        data=matches_df.to_csv(index=False).encode("utf-8"),
        file_name="indicator_matching_report.csv",
        mime="text/csv"
    )
