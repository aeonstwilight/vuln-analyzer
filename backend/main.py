from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from routers.analyze import router as analyze_router
from routers.compare import router as compare_router
from routers.report  import router as report_router

app = FastAPI(
    title="VulnAnalyzer API",
    description="Multi-vendor vulnerability scan analysis API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze_router)
app.include_router(compare_router)
app.include_router(report_router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/profiles")
def profiles():
    from core import COMPLIANCE_PROFILES, VER_PROFILES
    return {"profiles": list(COMPLIANCE_PROFILES.keys()) + list(VER_PROFILES.keys())}


# Serve built React frontend when dist/ exists (production / single-command mode)
_DIST = Path(__file__).parent.parent / "frontend" / "dist"
if _DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(_DIST / "assets")), name="assets")

    @app.get("/", include_in_schema=False)
    @app.get("/{catchall:path}", include_in_schema=False)
    def serve_spa(catchall: str = ""):
        return FileResponse(str(_DIST / "index.html"))
