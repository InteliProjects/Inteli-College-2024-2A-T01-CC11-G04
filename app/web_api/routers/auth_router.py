import logging
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from web_api.auth import (
    authenticate_user,
    create_access_token,
    get_current_active_user,
    create_user,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)

router = APIRouter()
logger = logging.getLogger(__name__)


# User creation and authentication routes
class UserCreate(BaseModel):
    username: str
    password: str
    full_name: str


@router.post("/users/create")
async def create_new_user(user: UserCreate):
    try:
        new_user = create_user(user.username, user.password, user.full_name)
        return {"message": "User created successfully", "user": new_user}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


class LoginCredentials(BaseModel):
    username: str
    password: str


@router.post("/token")
async def login_for_access_token(credentials: LoginCredentials):
    try:
        user = authenticate_user(credentials.username, credentials.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user["username"]}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error generating access token: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@router.get("/users/me")
async def read_users_me(current_user: dict = Depends(get_current_active_user)):
    return current_user
