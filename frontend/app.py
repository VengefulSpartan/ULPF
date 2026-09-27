import sys
from pathlib import Path

# Ensure repository root is on sys.path for Streamlit Cloud and container hosting
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st
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
        <div style="padding: 10px 4px 14px 4px; border-bottom: 1px solid rgba(255,255,255,0.08); margin-bottom: 12px;">
            <div style="display:flex; align-items:center; gap: 10px;">
                <div style="background: #0E1E31; width: 34px; height: 34px; border-radius: 6px; display:flex; align-items:center; justify-content:center; border: 1px solid #1E3A5F; flex-shrink: 0;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#38BDF8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <div>
                    <div style="font-size: 1.18rem; font-weight: 800; letter-spacing: 0.5px; color: #FFFFFF; line-height: 1.1;">TRACELOG</div>
                    <div style="font-size: 0.66rem; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 2px;">Universal Log Pre-processing</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <style>
        /* Scoped Modern Sidebar Navigation - Enterprise Styling */
        [data-testid="stSidebar"] [data-testid="stRadio"] > div {
            gap: 1px !important;
            padding: 0 !important;
        }

        /* 100% Guaranteed Elimination of White Circular Radio Bullets */
        [data-testid="stSidebar"] [data-testid="stRadio"] label[data-testid="stRadioOption"] > div > div:first-child,
        [data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"] > div > div:first-child,
        [data-testid="stSidebar"] [data-testid="stRadio"] label[data-testid="stRadioOption"] > div > :not([data-testid="stMarkdownContainer"]),
        [data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"] > div > :not([data-testid="stMarkdownContainer"]),
        [data-testid="stSidebar"] [data-testid="stRadio"] div[class*="e1mpz0hj4"],
        [data-testid="stSidebar"] [data-testid="stRadio"] div[class*="e1mpz0hj5"],
        [data-testid="stSidebar"] [data-testid="stRadio"] label[data-testid="stRadioOption"] input[type="radio"],
        [data-testid="stSidebar"] [data-testid="stRadio"] input[type="radio"],
        [data-testid="stSidebar"] [data-testid="stRadio"] span:has(input) {
            display: none !important;
            width: 0 !important;
            height: 0 !important;
            min-width: 0 !important;
            max-width: 0 !important;
            margin: 0 !important;
            padding: 0 !important;
            border: none !important;
            opacity: 0 !important;
            visibility: hidden !important;
            pointer-events: none !important;
        }

        /* Nav Item Container */
        [data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"],
        [data-testid="stSidebar"] [data-testid="stRadio"] label {
            display: flex !important;
            align-items: center !important;
            padding: 7px 12px !important;
            margin-bottom: 1px !important;
            cursor: pointer !important;
            transition: background-color 0.15s ease, border-left 0.15s ease !important;
            border: none !important;
            border-left: 3px solid transparent !important;
            border-radius: 0 4px 4px 0 !important;
            background-color: transparent !important;
        }

        /* Typography in Nav Items */
        [data-testid="stSidebar"] [data-testid="stRadio"] p {
            font-size: 0.84rem !important;
            font-weight: 500 !important;
            color: #94A3B8 !important;
            letter-spacing: 0.2px !important;
            margin: 0 !important;
            line-height: 1.4 !important;
            display: flex !important;
            align-items: center !important;
            transition: color 0.15s ease !important;
        }

        /* Base outline icon styling via p::before */
        [data-testid="stSidebar"] [data-testid="stRadio"] p::before {
            content: "";
            display: inline-block !important;
            width: 15px !important;
            height: 15px !important;
            margin-right: 10px !important;
            background-size: contain !important;
            background-repeat: no-repeat !important;
            background-position: center !important;
            vertical-align: -2px !important;
            flex-shrink: 0 !important;
            transition: opacity 0.15s ease !important;
        }

        /* Hover State */
        [data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"]:hover:not(:has(input:checked)),
        [data-testid="stSidebar"] [data-testid="stRadio"] label:hover:not(:has(input:checked)) {
            background-color: rgba(255, 255, 255, 0.04) !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"]:hover:not(:has(input:checked)) p,
        [data-testid="stSidebar"] [data-testid="stRadio"] label:hover:not(:has(input:checked)) p {
            color: #F1F5F9 !important;
        }

        /* Active Selected Item - Subtle Dark Blue with Left Cyan Accent (No Neon Glow) */
        [data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"]:has(input:checked),
        [data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"][data-selected="true"],
        [data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked),
        [data-testid="stSidebar"] [data-testid="stRadio"] label[data-selected="true"] {
            background-color: rgba(56, 189, 248, 0.08) !important;
            border: none !important;
            border-left: 3px solid #38BDF8 !important;
            border-radius: 0 4px 4px 0 !important;
            box-shadow: none !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"]:has(input:checked) p,
        [data-testid="stSidebar"] [data-testid="stRadio"] [data-testid="stRadioOption"][data-selected="true"] p,
        [data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) p {
            color: #F8FAFC !important;
            font-weight: 600 !important;
        }

        /* Section Group Headers */
        /* 1. WORKSPACE */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"]::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"]::before {
            content: "WORKSPACE";
            display: block;
            width: 100%;
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            color: #64748B;
            text-transform: uppercase;
            padding: 8px 12px 4px 12px;
            margin-bottom: 2px;
            pointer-events: none;
        }

        /* 2. SECURITY Header */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(6),
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(6) {
            margin-top: 14px !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(6)::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(6)::before {
            content: "SECURITY";
            display: block;
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            color: #64748B;
            text-transform: uppercase;
            padding: 0 12px 4px 12px;
            margin-bottom: 2px;
            pointer-events: none;
        }

        /* 3. DATA Header */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(8),
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(8) {
            margin-top: 14px !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(8)::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(8)::before {
            content: "DATA";
            display: block;
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            color: #64748B;
            text-transform: uppercase;
            padding: 0 12px 4px 12px;
            margin-bottom: 2px;
            pointer-events: none;
        }

        /* 4. SYSTEM Header */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(10),
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(10) {
            margin-top: 14px !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(10)::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(10)::before {
            content: "SYSTEM";
            display: block;
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            color: #64748B;
            text-transform: uppercase;
            padding: 0 12px 4px 12px;
            margin-bottom: 2px;
            pointer-events: none;
        }

        /* --- Monochrome Outline SVG Navigation Icons --- */
        /* 1. Overview */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(1) p::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(1) p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2394A3B8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='3' width='7' height='9'/%3E%3Crect x='14' y='3' width='7' height='5'/%3E%3Crect x='14' y='12' width='7' height='9'/%3E%3Crect x='3' y='16' width='7' height='5'/%3E%3C/svg%3E") !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(1):hover p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(1):has(input:checked) p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(1)[data-selected="true"] p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2338BDF8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='3' y='3' width='7' height='9'/%3E%3Crect x='14' y='3' width='7' height='5'/%3E%3Crect x='14' y='12' width='7' height='9'/%3E%3Crect x='3' y='16' width='7' height='5'/%3E%3C/svg%3E") !important;
        }

        /* 2. Sources & Onboarding */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(2) p::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(2) p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2394A3B8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='2' y='2' width='20' height='8' rx='2' ry='2'/%3E%3Crect x='2' y='14' width='20' height='8' rx='2' ry='2'/%3E%3Cline x1='6' y1='6' x2='6.01' y2='6'/%3E%3Cline x1='6' y1='18' x2='6.01' y2='18'/%3E%3C/svg%3E") !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(2):hover p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(2):has(input:checked) p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(2)[data-selected="true"] p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2338BDF8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='2' y='2' width='20' height='8' rx='2' ry='2'/%3E%3Crect x='2' y='14' width='20' height='8' rx='2' ry='2'/%3E%3Cline x1='6' y1='6' x2='6.01' y2='6'/%3E%3Cline x1='6' y1='18' x2='6.01' y2='18'/%3E%3C/svg%3E") !important;
        }

        /* 3. Parser Studio */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(3) p::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(3) p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2394A3B8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='4 17 10 11 4 5'/%3E%3Cline x1='12' y1='19' x2='20' y2='19'/%3E%3C/svg%3E") !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(3):hover p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(3):has(input:checked) p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(3)[data-selected="true"] p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2338BDF8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='4 17 10 11 4 5'/%3E%3Cline x1='12' y1='19' x2='20' y2='19'/%3E%3C/svg%3E") !important;
        }

        /* 4. Processing Pipeline */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(4) p::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(4) p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2394A3B8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='16 3 21 3 21 8'/%3E%3Cline x1='4' y1='20' x2='21' y2='3'/%3E%3Cpolyline points='21 16 21 21 16 21'/%3E%3Cline x1='15' y1='15' x2='21' y2='21'/%3E%3Cline x1='4' y1='4' x2='9' y2='9'/%3E%3C/svg%3E") !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(4):hover p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(4):has(input:checked) p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(4)[data-selected="true"] p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2338BDF8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='16 3 21 3 21 8'/%3E%3Cline x1='4' y1='20' x2='21' y2='3'/%3E%3Cpolyline points='21 16 21 21 16 21'/%3E%3Cline x1='15' y1='15' x2='21' y2='21'/%3E%3Cline x1='4' y1='4' x2='9' y2='9'/%3E%3C/svg%3E") !important;
        }

        /* 5. Log Explorer */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(5) p::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(5) p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2394A3B8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cline x1='21' y1='21' x2='16.65' y2='16.65'/%3E%3C/svg%3E") !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(5):hover p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(5):has(input:checked) p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(5)[data-selected="true"] p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2338BDF8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cline x1='21' y1='21' x2='16.65' y2='16.65'/%3E%3C/svg%3E") !important;
        }

        /* 6. Integrity & Lineage */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(6) p::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(6) p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2394A3B8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/%3E%3Cpolyline points='9 12 11 14 15 10'/%3E%3C/svg%3E") !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(6):hover p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(6):has(input:checked) p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(6)[data-selected="true"] p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2338BDF8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/%3E%3Cpolyline points='9 12 11 14 15 10'/%3E%3C/svg%3E") !important;
        }

        /* 7. Correlation & RCA */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(7) p::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(7) p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2394A3B8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='18' cy='5' r='3'/%3E%3Ccircle cx='6' cy='12' r='3'/%3E%3Ccircle cx='18' cy='19' r='3'/%3E%3Cline x1='8.59' y1='13.51' x2='15.42' y2='17.49'/%3E%3Cline x1='15.41' y1='6.51' x2='8.59' y2='10.49'/%3E%3C/svg%3E") !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(7):hover p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(7):has(input:checked) p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(7)[data-selected="true"] p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2338BDF8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='18' cy='5' r='3'/%3E%3Ccircle cx='6' cy='12' r='3'/%3E%3Ccircle cx='18' cy='19' r='3'/%3E%3Cline x1='8.59' y1='13.51' x2='15.42' y2='17.49'/%3E%3Cline x1='15.41' y1='6.51' x2='8.59' y2='10.49'/%3E%3C/svg%3E") !important;
        }

        /* 8. Schema Explorer */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(8) p::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(8) p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2394A3B8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cellipse cx='12' cy='5' rx='9' ry='3'/%3E%3Cpath d='M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5'/%3E%3Cpath d='M3 12c0 1.66 4 3 9 3s9-1.34 9-3'/%3E%3C/svg%3E") !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(8):hover p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(8):has(input:checked) p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(8)[data-selected="true"] p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2338BDF8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cellipse cx='12' cy='5' rx='9' ry='3'/%3E%3Cpath d='M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5'/%3E%3Cpath d='M3 12c0 1.66 4 3 9 3s9-1.34 9-3'/%3E%3C/svg%3E") !important;
        }

        /* 9. Connectors */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(9) p::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(9) p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2394A3B8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71'/%3E%3Cpath d='M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71'/%3E%3C/svg%3E") !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(9):hover p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(9):has(input:checked) p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(9)[data-selected="true"] p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2338BDF8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71'/%3E%3Cpath d='M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71'/%3E%3C/svg%3E") !important;
        }

        /* 10. Settings */
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(10) p::before,
        [data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] > div:nth-child(10) p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2394A3B8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='12' cy='12' r='3'/%3E%3Cpath d='M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z'/%3E%3C/svg%3E") !important;
        }
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(10):hover p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(10):has(input:checked) p::before,
        [data-testid="stSidebar"] [data-testid="stRadioGroup"] > div:nth-child(10)[data-selected="true"] p::before {
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%2338BDF8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='12' cy='12' r='3'/%3E%3Cpath d='M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z'/%3E%3C/svg%3E") !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Sources & Onboarding",
            "Parser Studio",
            "Processing Pipeline",
            "Log Explorer",
            "Integrity & Lineage",
            "Correlation & RCA",
            "Schema Explorer",
            "Connectors",
            "Settings"
        ],
        label_visibility="collapsed"
    )

    # Live backend health telemetry & footer badge
    is_online = APIClient.is_backend_online()
    api_color = "#22C55E" if is_online else "#FBBF24"
    api_status = "Online (:8000)" if is_online else "Direct Service Mode"

    st.markdown(
        f"""
        <div style="margin-top: 20px; padding-top: 14px; border-top: 1px solid rgba(255, 255, 255, 0.06);">
            <div style="display: inline-flex; align-items: center; gap: 6px; background: rgba(15, 23, 42, 0.7); border: 1px solid #1E293B; border-radius: 9999px; padding: 3px 10px; margin-bottom: 12px;">
                <span style="width: 6px; height: 6px; border-radius: 50%; background: #22C55E; display: inline-block;"></span>
                <span style="font-size: 0.65rem; font-weight: 600; color: #94A3B8; letter-spacing: 0.3px;">LOCAL / AIR-GAPPED DEMO</span>
            </div>
            <div style="background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 6px; padding: 10px 12px;">
                <div style="font-size: 0.65rem; font-weight: 700; color: #64748B; text-transform: uppercase; letter-spacing: 0.6px;">System Telemetry</div>
                <div style="font-size: 0.72rem; color: {api_color}; margin-top: 4px; display:flex; align-items:center; gap:6px;">
                    <span>●</span> <span>FastAPI Core: {api_status}</span>
                </div>
                <div style="font-size: 0.70rem; color: #94A3B8; margin-top: 3px;">
                    Storage: <span style="color:#F1F5F9;">SQLite (WAL Mode)</span>
                </div>
                <div style="font-size: 0.70rem; color: #94A3B8; margin-top: 1px;">
                    Integrity: <span style="color:#38BDF8;">SHA-256 Ledger</span>
                </div>
            </div>
            <div style="font-size:0.65rem; color:#475569; margin-top: 10px; text-align: center;">
                TRACELOG v1.0 · SIH 2026 · PS 26156
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

# Route to selected page
if page == "Overview":
    render_overview()
elif page == "Sources & Onboarding":
    render_sources()
elif page == "Parser Studio":
    render_parser_studio()
elif page == "Processing Pipeline":
    render_pipeline()
elif page == "Log Explorer":
    render_explorer()
elif page == "Integrity & Lineage":
    render_integrity()
elif page == "Correlation & RCA":
    render_correlation()
elif page == "Schema Explorer":
    render_schema()
elif page == "Connectors":
    render_integrations()
elif page == "Settings":
    render_settings()
