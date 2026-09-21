from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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
from backend.api.receivers import router as receivers_router


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Start syslog/file/Kafka inputs and output connectors from config/tracelog.yaml
    # (or the file named by TRACELOG_CONFIG). HTTP receivers are always mounted.
    await engine.start()
    yield
    await engine.stop()


app = FastAPI(
    lifespan=lifespan,
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise-grade Universal Log Pre-processing Framework for Perimeter Network Security",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for Streamlit frontend and local tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers under /api prefix
app.include_router(sources_router, prefix=settings.API_PREFIX)
app.include_router(ingestion_router, prefix=settings.API_PREFIX)
app.include_router(parsers_router, prefix=settings.API_PREFIX)
app.include_router(events_router, prefix=settings.API_PREFIX)
app.include_router(integrity_router, prefix=settings.API_PREFIX)
app.include_router(correlation_router, prefix=settings.API_PREFIX)
app.include_router(analytics_router, prefix=settings.API_PREFIX)
app.include_router(export_router, prefix=settings.API_PREFIX)
app.include_router(connectors_router, prefix=settings.API_PREFIX)
app.include_router(receivers_router)

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ULPF FastAPI Backend",
        "version": settings.VERSION,
        "database": "SQLite (WAL mode)",
        "db_path": str(settings.DB_PATH),
        "environment": settings.ENVIRONMENT
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.BACKEND_HOST,
        port=settings.BACKEND_PORT,
        reload=settings.DEBUG
    )
