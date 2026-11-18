import io
from collections import Counter
from datetime import datetime
import pandas as pd
import plotly.express as px
import streamlit as st
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR

st.set_page_config(page_title='Network Traffic Monitor', page_icon='🌐', layout='wide')
st.title('🌐 Network Traffic Monitoring & Analysis')
st.caption('Wireshark PCAP/PCAPNG analysis • Educational network monitoring')

@st.cache_data(show_spinner='Reading capture...')
def analyze(data):
    rows = []
    with PcapReader(io.BytesIO(data)) as packets:
        for i, pkt in enumerate(packets):
            if i >= 200000:
                break
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            transport = pkt.getlayer(TCP) or pkt.getlayer(UDP)
            sport = int(transport.sport) if transport else None
            dport = int(transport.dport) if transport else None
            if pkt.haslayer(DNS):
                proto = 'DNS'
            elif pkt.haslayer(TCP) and (sport == 80 or dport == 80):
                proto = 'HTTP'
            elif pkt.haslayer(TCP) and (sport == 443 or dport == 443):
                proto = 'TLS/HTTPS (port-based)'
            elif pkt.haslayer(UDP) and (sport == 443 or dport == 443):
                proto = 'QUIC/HTTPS (port-based)'
            elif pkt.haslayer(TCP):
                proto = 'TCP'
            elif pkt.haslayer(UDP):
                proto = 'UDP'
            else:
                proto = 'Other'
            dns_query = ''
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname
                dns_query = qname.decode('utf-8', errors='replace') if isinstance(qname, bytes) else str(qname)
            rows.append({'Time': datetime.fromtimestamp(float(pkt.time)), 'Source IP': str(ip.src) if ip else '',
                         'Destination IP': str(ip.dst) if ip else '', 'Source Port': sport,
                         'Destination Port': dport, 'Protocol': proto, 'Size (bytes)': len(pkt),
                         'TCP SYN': bool(pkt.haslayer(TCP) and int(pkt[TCP].flags) & 0x02 and not int(pkt[TCP].flags) & 0x10),
                         'DNS Query': dns_query})
    return pd.DataFrame(rows)

uploaded = st.file_uploader('Upload a Wireshark capture (.pcap / .pcapng)', type=['pcap', 'pcapng', 'cap'])
if uploaded is None:
    st.info('Capture traffic in Wireshark → File → Save As → .pcapng, then upload it here. No packets are captured by this app.')
    st.stop()
try:
    df = analyze(uploaded.getvalue())
except Exception as exc:
    st.error(f'Unable to parse capture: {exc}')
    st.stop()
if df.empty:
    st.warning('No packets found in the uploaded capture.')
    st.stop()

st.sidebar.header('Filters')
choices = sorted(df['Protocol'].unique())
selected = st.sidebar.multiselect('Protocols', choices, default=choices)
view = df[df['Protocol'].isin(selected)].copy()
if view.empty:
    st.warning('No packets match the filters.')
    st.stop()

c1,c2,c3,c4 = st.columns(4)
c1.metric('Packets', f'{len(view):,}')
c2.metric('Traffic', f'{view["Size (bytes)"].sum()/1024:.1f} KiB')
c3.metric('Unique source IPs', view.loc[view['Source IP'] != '', 'Source IP'].nunique())
c4.metric('DNS queries', (view['DNS Query'] != '').sum())

left,right = st.columns(2)
with left:
    counts = view['Protocol'].value_counts().reset_index()
    counts.columns = ['Protocol','Packets']
    st.plotly_chart(px.pie(counts, names='Protocol', values='Packets', title='Protocol distribution'), use_container_width=True)
with right:
    ports = view['Destination Port'].dropna().astype(int).value_counts().head(12).reset_index()
    ports.columns = ['Port','Packets']
    if not ports.empty:
        st.plotly_chart(px.bar(ports, x='Port', y='Packets', title='Top destination ports'), use_container_width=True)

trend = view.set_index('Time').resample('1s').size().reset_index(name='Packets')
st.plotly_chart(px.line(trend, x='Time', y='Packets', title='Packets over time'), use_container_width=True)
left,right = st.columns(2)
with left:
    ips = view.loc[view['Source IP'] != '', 'Source IP'].value_counts().head(10).reset_index()
    ips.columns = ['Source IP', 'Packets']
    st.subheader('Top source IPs')
    st.dataframe(ips, use_container_width=True, hide_index=True)
with right:
    st.subheader('Potentially unusual traffic')
    alerts = []
    # Heuristic thresholds are for demonstration, not proof of an attack.
    for ip, count in view.loc[view['Source IP'] != '', 'Source IP'].value_counts().items():
        if count >= 1000:
            alerts.append(f'High packet volume from {ip}: {count} packets')
    syns = view[view['TCP SYN'] & (view['Source IP'] != '')].groupby('Source IP').size()
    for ip, count in syns.items():
        if count >= 100:
            alerts.append(f'Repeated TCP SYN attempts from {ip}: {count}')
    if alerts:
        for alert in alerts[:20]:
            st.warning(alert)
    else:
        st.success('No predefined thresholds exceeded in filtered packets.')

st.subheader('Packet details')
st.dataframe(view.drop(columns=['TCP SYN']), use_container_width=True, hide_index=True)
st.download_button('Download filtered CSV', view.drop(columns=['TCP SYN']).to_csv(index=False).encode(), 'network_analysis.csv', 'text/csv')
st.caption('Protocol labels for HTTPS/QUIC are inferred from common ports; encrypted payloads are not decrypted. Alerts are only heuristics.')
