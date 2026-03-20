import io
import re
from typing import Any, Dict

import base64

import pandas as pd
import requests
import streamlit as st


st.set_page_config(page_title="Nemesis IoCs", layout="wide")


CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&display=swap');

:root {
    --bg: #101010;
    --panel: #1a1a1a;
    --text: #f1f1f1;
    --muted: #b7b7b7;
    --accent: #c48b52;
    --accent-2: #e6b07a;
    --border: rgba(255, 255, 255, 0.08);
}

html, body, [class*="stApp"] {
    font-family: 'Space Grotesk', sans-serif;
    color: var(--text);
    background: var(--bg);
}

#MainMenu, header, footer {
    visibility: hidden;
}

.app-shell {
    width: min(1200px, 92vw);
    margin: 0 auto;
    padding: 2rem 0 3rem;
}

.navbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 0 2rem;
    border-bottom: 1px solid var(--border);
}

.brand {
    font-weight: 700;
    font-size: 1.35rem;
    letter-spacing: 0.03em;
}

.brand span {
    color: var(--accent);
}

.nav-links {
    display: flex;
    gap: 1.5rem;
    font-size: 0.95rem;
    color: var(--muted);
}

.nav-links a {
    color: inherit;
    text-decoration: none;
}

.hero {
    position: relative;
    border-radius: 18px;
    padding: 3.5rem 3rem;
    margin-top: 2rem;
    background: linear-gradient(120deg, rgba(18,18,18,0.95) 10%, rgba(45,45,45,0.85) 60%, rgba(18,18,18,0.95) 100%),
                radial-gradient(circle at 20% 20%, rgba(196,139,82,0.25), transparent 55%);
    overflow: hidden;
    border: 1px solid var(--border);
}

.hero::after {
    content: "";
    position: absolute;
    inset: 0;
    background: linear-gradient(90deg, rgba(0,0,0,0.5), transparent 55%);
    pointer-events: none;
}

.hero h1 {
    font-size: clamp(2.2rem, 4vw, 3.6rem);
    color: var(--accent-2);
    margin: 0 0 1rem;
}

.hero p {
    max-width: 420px;
    color: var(--muted);
    margin: 0;
    font-size: 1.05rem;
}

.hero .cta {
    margin-top: 2rem;
    display: inline-block;
    padding: 0.75rem 1.6rem;
    border-radius: 999px;
    background: var(--accent);
    color: #1a1a1a;
    font-weight: 600;
    text-decoration: none;
}

.section-title {
    margin: 2.5rem 0 1rem;
    font-size: 1.2rem;
    color: var(--accent-2);
}

.panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 1.5rem;
}

.panel small {
    color: var(--muted);
}

.stButton > button {
    background: var(--accent);
    color: #1a1a1a;
    border-radius: 999px;
    border: none;
    padding: 0.6rem 1.4rem;
    font-weight: 600;
}

.stDownloadButton > button {
    background: transparent;
    color: var(--accent-2);
    border: 1px solid var(--accent);
    border-radius: 999px;
}

@media (max-width: 900px) {
    .navbar {
        flex-direction: column;
        gap: 0.75rem;
        align-items: flex-start;
    }

    .nav-links {
        flex-wrap: wrap;
        gap: 0.75rem 1.1rem;
    }

    .hero {
        padding: 2.5rem 2rem;
    }
}
</style>
"""


st.markdown(CSS, unsafe_allow_html=True)

st.markdown(
    """
<div class="app-shell">
    <div class="navbar">
        <div class="brand">Nemesis<span>.</span></div>
        <div class="nav-links">
            <a href="#">Home</a>
            <a href="#">Methodology</a>
            <a href="#">About Us</a>
            <a href="#">Why Us</a>
            <a href="#">Contact</a>
        </div>
    </div>
    <div class="hero">
        <h1>Ciberdefensa para empresas que no se la juegan</h1>
        <p>Analiza IoCs con fuentes abiertas. Genera una matriz de riesgo y descarga los resultados en Excel.</p>
        <a class="cta" href="#consulta">Consultar IoCs</a>
    </div>
</div>
""",
    unsafe_allow_html=True,
)


def detect_ioc_type(ioc: str) -> str:
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, ioc):
        return "ip"

    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", ioc):
        return "file"

    return "domain"


def vt_url_id(url: str) -> str:
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
    return encoded.rstrip("=")


def query_virustotal(ioc: str, ioc_type: str, api_key: str) -> Dict[str, Any]:
    base_url = "https://www.virustotal.com/api/v3"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    endpoint_map = {
        "url": f"/urls/{vt_url_id(ioc)}",
        "ip": f"/ip_addresses/{ioc}",
        "domain": f"/domains/{ioc}",
        "file": f"/files/{ioc}",
    }

    try:
        response = requests.get(
            f"{base_url}{endpoint_map[ioc_type]}",
            headers=headers,
            timeout=20,
        )
    except requests.RequestException as exc:
        return {
            "ioc": ioc,
            "type": ioc_type,
            "source": "VirusTotal",
            "query_status": "error",
            "malicious": "error",
            "threat": None,
            "tags": None,
            "last_seen": None,
            "pulse_count": None,
            "detection_count": None,
            "error": str(exc),
            "raw": None,
        }

    if response.status_code == 404:
        return {
            "ioc": ioc,
            "type": ioc_type,
            "source": "VirusTotal",
            "query_status": "not_found",
            "malicious": "no",
            "threat": None,
            "tags": None,
            "last_seen": None,
            "pulse_count": None,
            "detection_count": 0,
            "error": None,
            "raw": None,
        }

    if not response.ok:
        return {
            "ioc": ioc,
            "type": ioc_type,
            "source": "VirusTotal",
            "query_status": "error",
            "malicious": "error",
            "threat": None,
            "tags": None,
            "last_seen": None,
            "pulse_count": None,
            "detection_count": None,
            "error": f"HTTP {response.status_code}",
            "raw": None,
        }

    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious_count = int(stats.get("malicious", 0) or 0)
    suspicious_count = int(stats.get("suspicious", 0) or 0)
    detection_count = malicious_count + suspicious_count

    tags = None
    if isinstance(attributes.get("tags"), list):
        tags = ", ".join(attributes.get("tags", []))

    last_seen = (
        attributes.get("last_modification_date")
        or attributes.get("last_analysis_date")
        or attributes.get("last_seen_itw_date")
    )

    return {
        "ioc": ioc,
        "type": ioc_type,
        "source": "VirusTotal",
        "query_status": "ok",
        "malicious": "yes" if detection_count > 0 else "no",
        "threat": attributes.get("type_description"),
        "tags": tags,
        "last_seen": last_seen,
        "pulse_count": None,
        "detection_count": detection_count,
        "error": None,
        "raw": data,
    }


st.markdown("<div class=\"app-shell\" id=\"consulta\">", unsafe_allow_html=True)

st.markdown("<div class=\"section-title\">Consulta tus IoCs</div>", unsafe_allow_html=True)

with st.container():
    st.markdown("<div class=\"panel\">", unsafe_allow_html=True)

    ioc_text = st.text_area(
        "IoCs (uno por linea)",
        height=200,
        placeholder="http://malicioso.tld/path\n8.8.8.8\n0c99481d...",
    )
    api_key = st.text_input("VirusTotal API Key", type="password")
    st.caption(
        "Se admite URL, IP, dominio/host y hashes MD5/SHA1/SHA256. "
        "VirusTotal requiere API key."
    )

    run = st.button("Consultar IoCs", type="primary")
    st.markdown("</div>", unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)

if run:
    if not ioc_text.strip():
        st.error("Agrega al menos un IoC.")
    elif not api_key:
        st.error("Agrega tu API Key.")
    else:
        iocs = [line.strip() for line in ioc_text.splitlines() if line.strip()]
        results = []
        for ioc in iocs:
            ioc_type = detect_ioc_type(ioc)
            results.append(query_virustotal(ioc, ioc_type, api_key))

        df = pd.DataFrame(results)

        st.markdown("<div class=\"app-shell\">", unsafe_allow_html=True)
        st.markdown("<div class=\"section-title\">Matriz de resultados</div>", unsafe_allow_html=True)

        st.dataframe(df.drop(columns=["raw"]))

        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.drop(columns=["raw"]).to_excel(writer, index=False, sheet_name="IoCs")
        output.seek(0)

        st.download_button(
            "Descargar XLSX",
            data=output,
            file_name="iocs_matrix.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

        with st.expander("Ver respuestas crudas"):
            st.json([item["raw"] for item in results])

        st.markdown("</div>", unsafe_allow_html=True)
