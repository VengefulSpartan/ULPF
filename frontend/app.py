import streamlit as st
from pathlib import Path
from frontend.api_client import APIClient

# Page setup
st.set_page_config(
    page_title="TRACELOG — Universal Log Pre-processing Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load custom CSS
css_path = Path(__file__).parent / "assets" / "style.css"
if css_path.exists():
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Import page renderers
from frontend.views.overview_page import render_overview
from frontend.views.sources_page import render_sources
from frontend.views.parser_studio_page import render_parser_studio
from frontend.views.pipeline_page import render_pipeline
from frontend.views.explorer_page import render_explorer
from frontend.views.integrity_page import render_integrity
from frontend.views.correlation_page import render_correlation
from frontend.views.schema_page import render_schema
from frontend.views.integrations_page import render_integrations
from frontend.views.settings_page import render_settings

# Sidebar Branding & Navigation
with st.sidebar:
    st.markdown(
        """
        <div style="padding: 12px 4px 16px 4px; border-bottom: 1px solid rgba(255,255,255,0.08); margin-bottom: 15px;">
            <div style="display:flex; align-items:center; gap: 12px;">
                <div style="background: linear-gradient(135deg, #0077B6 0%, #123B5D 100%); width: 40px; height: 40px; border-radius: 8px; display:flex; align-items:center; justify-content:center; font-size:1.3rem; box-shadow: 0 4px 12px rgba(0, 119, 182, 0.35); border: 1px solid rgba(56, 189, 248, 0.4);">
                    🛡️
                </div>
                <div>
                    <div style="font-size: 1.35rem; font-weight: 800; letter-spacing: 0.8px; color: #FFFFFF; line-height: 1.1;">TRACELOG</div>
                    <div style="font-size: 0.7rem; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 2px;">Universal Log Pre-processing</div>
                </div>
            </div>
            <div style="background: rgba(0, 119, 182, 0.15); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 6px; padding: 6px 10px; margin-top: 14px; display:flex; align-items:center; gap: 8px;">
                <span style="width: 7px; height: 7px; border-radius: 50%; background: #4ADE80; box-shadow: 0 0 6px #4ADE80; display: inline-block;"></span>
                <span style="font-size: 0.72rem; font-weight: 600; color: #38BDF8; letter-spacing: 0.4px;">LOCAL / AIR-GAPPED DEMO</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    page = st.radio(
        "Navigation",
        [
            "📊  Overview",
            "🔌  Sources & Onboarding",
            "⚡  Parser Studio",
            "🔄  Processing Pipeline",
            "🔎  Log Explorer",
            "🛡️  Integrity & Lineage",
            "🧬  Correlation & RCA",
            "📐  Schema Explorer",
            "🔗  Connectors",
            "⚙️  Settings"
        ],
        label_visibility="collapsed"
    )

    # Live backend health telemetry card
    is_online = APIClient.is_backend_online()
    api_color = "#4ADE80" if is_online else "#FBBF24"
    api_status = "Online (:8000)" if is_online else "Direct Service Mode"

    st.markdown(
        f"""
        <div style="background: rgba(15, 23, 42, 0.65); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 6px; padding: 12px; margin-top: 22px;">
            <div style="font-size: 0.68rem; font-weight: 700; color: #64748B; text-transform: uppercase; letter-spacing: 0.6px;">System Telemetry</div>
            <div style="font-size: 0.75rem; color: {api_color}; margin-top: 6px; display:flex; align-items:center; gap:6px;">
                <span>●</span> <span>FastAPI Core: {api_status}</span>
            </div>
            <div style="font-size: 0.72rem; color: #94A3B8; margin-top: 4px;">
                Storage: <span style="color:#F1F5F9;">SQLite (WAL Mode)</span>
            </div>
            <div style="font-size: 0.72rem; color: #94A3B8; margin-top: 2px;">
                Integrity: <span style="color:#38BDF8;">SHA-256 Ledger</span>
            </div>
        </div>
        <div style="font-size:0.68rem; color:#475569; margin-top: 12px; text-align: center;">
            TRACELOG v1.0 · SIH 2026 · PS 26156
        </div>
        """,
        unsafe_allow_html=True
    )

# Route to selected page
if "Overview" in page:
    render_overview()
elif "Sources" in page:
    render_sources()
elif "Parser Studio" in page:
    render_parser_studio()
elif "Processing Pipeline" in page:
    render_pipeline()
elif "Log Explorer" in page:
    render_explorer()
elif "Integrity" in page:
    render_integrity()
elif "Correlation" in page:
    render_correlation()
elif "Schema Explorer" in page:
    render_schema()
elif "Connectors" in page:
    render_integrations()
elif "Settings" in page:
    render_settings()
