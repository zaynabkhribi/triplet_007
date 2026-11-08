from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class CityBrainError(Exception):
    status_code = 400
    code = "city_brain_error"


class TrustRejectedError(CityBrainError):
    status_code = 403
    code = "trust_rejected"


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def handle_validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": error["loc"], "type": error["type"], "msg": error["msg"]}
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    @app.exception_handler(CityBrainError)
    async def handle_city_brain_error(_: Request, exc: CityBrainError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": str(exc)}},
        )
