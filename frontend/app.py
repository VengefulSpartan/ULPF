import os
import sys
from pathlib import Path

# before streamlit and pandas load numpy: one BLAS thread (backend/services/ml/__init__.py says why)
for _name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_name, "1")

# the repository root on sys.path, for Streamlit Community Cloud and container hosting
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402
from backend.config import settings  # noqa: E402
from frontend import ui  # noqa: E402
from frontend.api_client import APIClient  # noqa: E402

st.set_page_config(page_title="TRACELOG", page_icon=str(ui.ASSETS / "logo-mark.svg"), layout="wide",
                   initial_sidebar_state=236)
ui.apply_theme()
st.logo(str(ui.ASSETS / "logo.svg"), size="large", icon_image=str(ui.ASSETS / "logo-mark.svg"))

from frontend.views.overview_page import render_overview  # noqa: E402
from frontend.views.sources_page import render_sources  # noqa: E402
from frontend.views.parser_studio_page import render_parser_studio  # noqa: E402
from frontend.views.pipeline_page import render_pipeline  # noqa: E402
from frontend.views.explorer_page import render_explorer  # noqa: E402
from frontend.views.integrity_page import render_integrity  # noqa: E402
from frontend.views.correlation_page import render_correlation  # noqa: E402
from frontend.views.schema_page import render_schema  # noqa: E402
from frontend.views.integrations_page import render_integrations  # noqa: E402
from frontend.views.settings_page import render_settings  # noqa: E402

# Each page has its own address (/log-explorer, /integrity …), so a page can be bookmarked or linked.
PAGES = {
    "Workspace": [
        st.Page(render_overview, title="Overview", url_path="overview", icon=":material/space_dashboard:", default=True),
        st.Page(render_sources, title="Sources", url_path="sources", icon=":material/dns:"),
        st.Page(render_parser_studio, title="Parser Studio", url_path="parser-studio", icon=":material/data_object:"),
        st.Page(render_pipeline, title="Pipeline", url_path="pipeline", icon=":material/account_tree:"),
        st.Page(render_explorer, title="Log Explorer", url_path="log-explorer", icon=":material/search:"),
    ],
    "Security": [
        st.Page(render_integrity, title="Integrity", url_path="integrity", icon=":material/verified_user:"),
        st.Page(render_correlation, title="Correlation", url_path="correlation", icon=":material/hub:"),
    ],
    "Data": [
        st.Page(render_schema, title="Schema", url_path="schema", icon=":material/schema:"),
        st.Page(render_integrations, title="Connectors", url_path="connectors", icon=":material/cable:"),
    ],
    "System": [
        st.Page(render_settings, title="Settings", url_path="settings", icon=":material/settings:"),
    ],
}
page = st.navigation(PAGES, expanded=True)


hosted = None
if settings.HOSTED_DEMO:
    # Streamlit Community Cloud runs only this script: start the API and two witnesses beside it, once per
    # process (backend/hosted_demo.py). The dict it returns keeps changing as the demo data loads.
    @st.cache_resource(show_spinner="Starting the TRACELOG API and two witnesses…")
    def _start_hosted_demo():
        from backend import hosted_demo
        return hosted_demo.start()

    hosted = _start_hosted_demo()


@st.cache_data(ttl=5, show_spinner=False)
def _api_online() -> bool:
    return APIClient.is_backend_online()


is_online = _api_online()
with st.sidebar:
    st.markdown(ui.status_block(is_online, settings.DASHBOARD_DIRECT_MODE, settings.BACKEND_HOST, settings.BACKEND_PORT,
                                hosted=hosted), unsafe_allow_html=True)

if not is_online and not settings.DASHBOARD_DIRECT_MODE:
    # the containers: the dashboard never runs the backend itself (frontend/api_client.py says why)
    st.error(f"The TRACELOG API at {settings.BACKEND_HOST}:{settings.BACKEND_PORT} is not answering. "
             "Check the services with `docker compose ps` and `docker compose logs gateway collector query`.")
    st.stop()

page.run()
