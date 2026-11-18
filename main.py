"""FastAPI service for phishing URL detection.

Run:  uvicorn main:app --reload
Docs: http://127.0.0.1:8000/docs
"""
import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from detector import InvalidURL, analyze

log = logging.getLogger("phishing-api")

app = FastAPI(
    title="Phishing URL Detection API",
    description="Detects phishing URLs using a machine-learning model plus safety rules",
    version="2.0.0",
)
# "*" origins cannot be combined with credentials, and we don't use cookies -> no credentials
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class URLRequest(BaseModel):
    url: str = Field(..., max_length=10_000)


@app.get("/")
def home():
    return {"message": "Phishing URL Detection API is running", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/predict")
def predict(request: URLRequest):
    try:
        return {"success": True, **analyze(request.url)}
    except InvalidURL as e:  # user typed something that isn't a link -> 422, NOT "safe"
        raise HTTPException(status_code=422, detail={"code": e.code, "message": e.message})
    except Exception:
        log.exception("prediction failed")
        raise HTTPException(status_code=500, detail={"code": "internal", "message": "Internal error."})
