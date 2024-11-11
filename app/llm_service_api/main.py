# main.py
from fastapi import FastAPI
from .routers import faq_router

app = FastAPI()

app.include_router(faq_router.router)

@app.get("/")
def root():
    return {"message": "Welcome to the FAQ API"}
