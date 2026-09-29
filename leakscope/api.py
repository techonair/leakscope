from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from leakscope.models import TriageRequest, TriageResult
from leakscope.service import TriageService

app = FastAPI(title="LeakScope", version="0.1.0")
service = TriageService()


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request. Check required fields and documented length limits."},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.1.0"}


@app.post("/v1/triage", response_model=TriageResult)
def triage(request: TriageRequest) -> TriageResult:
    return service.triage(request)
