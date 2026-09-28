from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles
from backend.config import settings
from backend.connectors.engine import engine
from backend.services.storage.db import db

# Import routers
from backend.api.sources import router as sources_router
from backend.api.ingestion import router as ingestion_router
from backend.api.parsers import router as parsers_router
from backend.api.events import router as events_router
from backend.api.integrity import router as integrity_router
from backend.api.correlation import router as correlation_router
from backend.api.analytics import router as analytics_router
from backend.api.export import router as export_router
from backend.api.connectors import router as connectors_router
from backend.api.audit import router as audit_router
from backend.api.formats import router as formats_router
from backend.api.receivers import router as receivers_router
from backend.api.ml import router as ml_router
from backend.api.evidence import router as evidence_router
from backend.api.compliance import router as compliance_router
from backend.services.integrity import checkpoints, signing
from backend.services.ml import baseline


# Every API router, mounted under /api. The receivers (HEC, OTLP) are mounted at the root.
ROUTERS = [sources_router, ingestion_router, parsers_router, events_router, integrity_router, correlation_router,
           analytics_router, export_router, connectors_router, audit_router, formats_router, ml_router,
           evidence_router, compliance_router]

# What the query service serves: the GET requests of these routers, which read the archive and never
# change it (tests/test_services.py checks each one against a read-only database). /connectors is
# not here: it reports the collector's live inputs and outputs, which only the collector has.
QUERY_ROUTERS = ("/events", "/integrity", "/analytics", "/export", "/audit", "/correlation", "/ml", "/formats",
                 "/sources", "/parsers", "/evidence", "/compliance")


def _reads_only(router: APIRouter) -> APIRouter:
    """The router's GET routes (their paths already carry the router's prefix), and nothing that changes data."""
    reads = APIRouter()
    reads.routes = [r for r in router.routes if isinstance(r, APIRoute) and r.methods <= {"GET", "HEAD"}]
    return reads


@asynccontextmanager
async def collector_lifespan(_app: FastAPI):
    # Start syslog/file/Kafka inputs and output connectors from config/tracelog.yaml
    # (or the file named by TRACELOG_CONFIG). HTTP receivers are always mounted.
    await engine.start()
    detector = baseline.Schedule(settings.BASELINE_EVERY_MINUTES).start() if settings.BASELINE_EVERY_MINUTES > 0 \
        else None
    # seal what is not yet in a signed checkpoint and ask the witnesses to countersign it
    sealer = checkpoints.Schedule(settings.CHECKPOINT_EVERY_SECONDS).start() \
        if settings.CHECKPOINT_EVERY_SECONDS > 0 and signing.HAVE_CRYPTO else None
    yield
    if sealer:
        sealer.stop()
    if detector:
        detector.stop()
    await engine.stop()


SERVICE_NAMES = {"all": "TRACELOG API", "collector": "TRACELOG collector", "query": "TRACELOG query"}


def create_app(role: str = "all") -> FastAPI:
    """
    The API for one service role (setting SERVICE_ROLE, docs/SERVICES.md):

    - "all"       everything in one process: python run_app.py, and the tests;
    - "collector" the same routes, plus the inputs, the one writer and the outputs it starts; the
                  gateway sends it every request except the reads the query service answers;
    - "query"     only the GET routes of QUERY_ROUTERS, on a read-only database, and no inputs,
                  writer or outputs, so a heavy search, audit report or chain verification never
                  slows ingestion down and the service that answers analysts cannot alter evidence.
    """
    application = FastAPI(
        lifespan=None if role == "query" else collector_lifespan,
        title=settings.PROJECT_NAME if role == "all" else f"{settings.PROJECT_NAME} ({role})",
        version=settings.VERSION,
        description="TRACELOG: receives perimeter device logs, archives each line, normalises it to OCSF 1.1.0, hash-chains it and forwards it to SIEM and observability tools (SIH 2026, PS 26156).",
        # FastAPI's own /docs page loads Swagger UI from a CDN and is blank on an air-gapped network
        # (PS item j). The same files ship in backend/static/swagger-ui and /docs below serves them.
        # ReDoc would need a second CDN bundle and is not offered.
        docs_url=None,
        redoc_url=None,
    )
    application.mount("/static/swagger-ui", StaticFiles(directory=SWAGGER_UI), name="swagger-ui")

    @application.get("/docs", include_in_schema=False)
    def swagger_ui():
        return get_swagger_ui_html(
            openapi_url=application.openapi_url,
            title=f"{settings.PROJECT_NAME} API",
            swagger_js_url="/static/swagger-ui/swagger-ui-bundle.js",
            swagger_css_url="/static/swagger-ui/swagger-ui.css",
            swagger_favicon_url="/static/swagger-ui/favicon-32x32.png",
            # Swagger UI would otherwise ask validator.swagger.io to check the spec
            swagger_ui_parameters={"validatorUrl": None},
        )

    # Enable CORS for Streamlit frontend and local tools
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API Routers under /api prefix
    for router in ROUTERS:
        if role != "query":
            application.include_router(router, prefix=settings.API_PREFIX)
        elif router.prefix in QUERY_ROUTERS:
            application.include_router(_reads_only(router), prefix=settings.API_PREFIX)
    if role != "query":
        application.include_router(receivers_router)

    @application.get("/health")
    def health_check():
        return {
            "status": "healthy",
            "service": SERVICE_NAMES[role],
            "role": role,
            "version": settings.VERSION,
            "database": "SQLite (WAL mode)" + (", read-only" if settings.DB_READ_ONLY else ""),
            "db_path": str(settings.DB_PATH),
            "environment": settings.ENVIRONMENT
        }

    return application


SWAGGER_UI = Path(__file__).parent / "static" / "swagger-ui"
app = create_app(settings.SERVICE_ROLE)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.DEBUG
    )
