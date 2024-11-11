from fastapi import FastAPI
from .routers.base_router import router as base_router
from .config.settings import settings

app = FastAPI()

app.include_router(base_router, prefix=settings.API_STR)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.HOST, port=settings.PORT)
