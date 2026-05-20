from http import HTTPStatus

from fastapi import FastAPI

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/api/v1/health")
def health() -> dict[str, str]:
    return {"status": HTTPStatus.OK.phrase}
