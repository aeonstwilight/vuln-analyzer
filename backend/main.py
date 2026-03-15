from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers.analyze import router as analyze_router
from routers.compare import router as compare_router
from routers.report  import router as report_router

app = FastAPI(
    title="VulnAnalyzer API",
    description="Multi-vendor vulnerability scan analysis API",
    version="1.0.0",
)

# Allow React dev server to call the API during development
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
    from core import COMPLIANCE_PROFILES
    return {"profiles": list(COMPLIANCE_PROFILES.keys())}
