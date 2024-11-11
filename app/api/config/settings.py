from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    API_STR: str = "/api/v1"  
    HOST: str = "127.0.0.1"       
    PORT: int = 8000              

    DEBUG: bool = False           

    class Config:
        env_file = ".env"  

settings = Settings()