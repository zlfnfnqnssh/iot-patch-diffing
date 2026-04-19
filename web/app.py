"""FastAPI server entry — Patch-Learner local dashboard.

Run:
    cd D:\\Task\\4\\project\\web
    python -m venv .venv && .\\.venv\\Scripts\\activate
    pip install -r requirements.txt
    python app.py
    -> http://127.0.0.1:8787
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from api.routes_dashboard import router as dashboard_router
from api.routes_cards import router as cards_router
from api.routes_sessions import router as sessions_router
from api.routes_zero_day import router as zero_day_router

BASE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE / "templates"))

app = FastAPI(title="Patch-Learner Dashboard", version="0.1")
app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

app.include_router(dashboard_router)
app.include_router(cards_router)
app.include_router(sessions_router)
app.include_router(zero_day_router)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request, "dashboard.html", {"page": "dashboard"})


@app.get("/cards", response_class=HTMLResponse)
def cards_page(request: Request):
    return templates.TemplateResponse(request, "cards.html", {"page": "cards"})


@app.get("/cards/{pk}", response_class=HTMLResponse)
def card_detail_page(request: Request, pk: int):
    return templates.TemplateResponse(request, "card_detail.html", {"page": "cards", "pk": pk})


@app.get("/sessions", response_class=HTMLResponse)
def sessions_page(request: Request):
    return templates.TemplateResponse(request, "sessions.html", {"page": "sessions"})


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request):
    return templates.TemplateResponse(request, "findings.html", {"page": "findings"})


@app.get("/zero-day", response_class=HTMLResponse)
def zero_day_list(request: Request):
    return templates.TemplateResponse(request, "zero_day_list.html", {"page": "zero_day"})


@app.get("/zero-day/{run_id}", response_class=HTMLResponse)
def zero_day_detail(request: Request, run_id: int):
    return templates.TemplateResponse(request, "zero_day_detail.html", {"page": "zero_day", "run_id": run_id})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8787, reload=False)
