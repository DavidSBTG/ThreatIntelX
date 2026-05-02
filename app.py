import os
import re
import requests
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

st.set_page_config(
    page_title="ThreatIntelX",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main {
        background-color: #0f172a;
    }
    .block-container {
        padding-top: 1.5rem;
    }
    .intel-card {
        background: linear-gradient(135deg, #111827, #1e293b);
        border: 1px solid #334155;
        border-radius: 16px;
        padding: 20px;
        box-shadow: 0 0 18px rgba(0,0,0,0.35);
    }
    .small-muted {
        color: #94a3b8;
        font-size: 14px;
    }
    .risk-low {
        color: #22c55e;
        font-size: 32px;
        font-weight: 800;
    }
    .risk-medium {
        color: #f59e0b;
        font-size: 32px;
        font-weight: 800;
    }
    .risk-high {
        color: #ef4444;
        font-size: 32px;
        font-weight: 800;
    }
</style>
""", unsafe_allow_html=True)


def is_ip(value: str) -> bool:
    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, value):
        return False
    return all(0 <= int(part) <= 255 for part in value.split("."))


def is_domain(value: str) -> bool:
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    return bool(re.match(pattern, value))


def calculate_risk_score(abuse_score: int = 0, vt_malicious: int = 0, vt_suspicious: int = 0) -> int:
    score = 0
    score += min(abuse_score, 100)
    score += vt_malicious * 15
    score += vt_suspicious * 7
    return min(score, 100)


def risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def abuseipdb_lookup(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY fehlt. Lege eine .env Datei an."}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        if response.status_code == 401:
            return {"error": "AbuseIPDB API-Key ungültig oder fehlt."}
        if response.status_code == 429:
            return {"error": "AbuseIPDB Rate Limit erreicht."}
        response.raise_for_status()
        return response.json().get("data", {})
    except requests.RequestException as e:
        return {"error": f"AbuseIPDB Fehler: {e}"}


def virustotal_lookup(query: str, query_type: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VIRUSTOTAL_API_KEY fehlt. Lege eine .env Datei an."}

    if query_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{query}"

    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 401:
            return {"error": "VirusTotal API-Key ungültig oder fehlt."}
        if response.status_code == 429:
            return {"error": "VirusTotal Rate Limit erreicht."}
        response.raise_for_status()
        return response.json().get("data", {}).get("attributes", {})
    except requests.RequestException as e:
        return {"error": f"VirusTotal Fehler: {e}"}


st.sidebar.title("🧠 ThreatIntelX")
st.sidebar.caption("SOC Threat Intelligence Dashboard")
st.sidebar.markdown("---")
st.sidebar.write("Unterstützt:")
st.sidebar.write("✅ IP Lookup")
st.sidebar.write("✅ Domain Lookup")
st.sidebar.write("✅ AbuseIPDB")
st.sidebar.write("✅ VirusTotal")
st.sidebar.markdown("---")

st.title("🧠 ThreatIntelX")
st.caption("Threat Intelligence Tool for SOC Analysts | IP & Domain Reputation Scanner")

query = st.text_input("IP oder Domain eingeben", placeholder="Beispiel: 8.8.8.8 oder example.com")
scan_button = st.button("🔍 Analyze Threat Intel")

if scan_button:
    query = query.strip()

    if not query:
        st.warning("Bitte IP oder Domain eingeben.")
        st.stop()

    if is_ip(query):
        query_type = "ip"
    elif is_domain(query):
        query_type = "domain"
    else:
        st.error("Ungültiges Format. Bitte gültige IPv4-Adresse oder Domain eingeben.")
        st.stop()

    with st.spinner("Threat Intelligence wird abgefragt..."):
        abuse_data = {}
        if query_type == "ip":
            abuse_data = abuseipdb_lookup(query)

        vt_data = virustotal_lookup(query, query_type)

    abuse_score = 0
    country = "Unknown"
    isp = "Unknown"
    domain = "Unknown"
    usage_type = "Unknown"
    total_reports = 0

    if query_type == "ip" and abuse_data and "error" not in abuse_data:
        abuse_score = abuse_data.get("abuseConfidenceScore", 0) or 0
        country = abuse_data.get("countryCode", "Unknown")
        isp = abuse_data.get("isp", "Unknown")
        domain = abuse_data.get("domain", "Unknown")
        usage_type = abuse_data.get("usageType", "Unknown")
        total_reports = abuse_data.get("totalReports", 0) or 0

    vt_malicious = 0
    vt_suspicious = 0
    vt_harmless = 0
    vt_undetected = 0

    if vt_data and "error" not in vt_data:
        stats = vt_data.get("last_analysis_stats", {})
        vt_malicious = stats.get("malicious", 0) or 0
        vt_suspicious = stats.get("suspicious", 0) or 0
        vt_harmless = stats.get("harmless", 0) or 0
        vt_undetected = stats.get("undetected", 0) or 0

        if query_type == "domain":
            country = vt_data.get("country", "Unknown")
            domain = query

    final_score = calculate_risk_score(abuse_score, vt_malicious, vt_suspicious)
    final_level = risk_level(final_score)

    st.markdown("---")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown('<div class="intel-card">', unsafe_allow_html=True)
        st.markdown('<div class="small-muted">Target</div>', unsafe_allow_html=True)
        st.subheader(query)
        st.write(query_type.upper())
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="intel-card">', unsafe_allow_html=True)
        st.markdown('<div class="small-muted">Risk Level</div>', unsafe_allow_html=True)
        css_class = "risk-high" if final_level == "HIGH" else "risk-medium" if final_level == "MEDIUM" else "risk-low"
        st.markdown(f'<div class="{css_class}">{final_level}</div>', unsafe_allow_html=True)
        st.write(f"Score: {final_score}/100")
        st.markdown('</div>', unsafe_allow_html=True)

    with col3:
        st.markdown('<div class="intel-card">', unsafe_allow_html=True)
        st.markdown('<div class="small-muted">Country</div>', unsafe_allow_html=True)
        st.subheader(country)
        st.write(f"ISP: {isp}")
        st.markdown('</div>', unsafe_allow_html=True)

    with col4:
        st.markdown('<div class="intel-card">', unsafe_allow_html=True)
        st.markdown('<div class="small-muted">Reports</div>', unsafe_allow_html=True)
        st.subheader(total_reports)
        st.write(f"Abuse Score: {abuse_score}")
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("---")

    left, right = st.columns(2)

    with left:
        st.subheader("🛡️ AbuseIPDB Result")
        if query_type != "ip":
            st.info("AbuseIPDB wird in v1 nur für IP-Adressen genutzt.")
        elif "error" in abuse_data:
            st.warning(abuse_data["error"])
        else:
            abuse_table = pd.DataFrame([{
                "IP": abuse_data.get("ipAddress"),
                "Country": country,
                "ISP": isp,
                "Domain": domain,
                "Usage Type": usage_type,
                "Abuse Score": abuse_score,
                "Total Reports": total_reports
            }])
            st.dataframe(abuse_table, use_container_width=True)

    with right:
        st.subheader("🧬 VirusTotal Result")
        if "error" in vt_data:
            st.warning(vt_data["error"])
        else:
            vt_table = pd.DataFrame([{
                "Malicious": vt_malicious,
                "Suspicious": vt_suspicious,
                "Harmless": vt_harmless,
                "Undetected": vt_undetected
            }])
            st.dataframe(vt_table, use_container_width=True)
            st.bar_chart(vt_table.T)

    st.markdown("---")
    st.subheader("🔎 Analyst Summary")

    if final_level == "HIGH":
        st.error("Hohe Bedrohung: Diese IP/Domain sollte blockiert, genauer untersucht oder in einem Incident dokumentiert werden.")
    elif final_level == "MEDIUM":
        st.warning("Mittlere Bedrohung: Weitere Prüfung empfohlen, besonders bei Login-Versuchen oder Verbindungen aus deinem Netzwerk.")
    else:
        st.success("Niedrige Bedrohung: Aktuell keine starke Reputationsauffälligkeit erkannt.")

else:
    st.info("Gib eine IP oder Domain ein und starte die Analyse.")