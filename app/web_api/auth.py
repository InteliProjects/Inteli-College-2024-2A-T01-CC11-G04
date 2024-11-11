import logging
from datetime import datetime, timedelta
from typing import Optional

import jwt  # PyJWT
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# JWT settings
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Simulated in-memory database
fake_users_db = {}

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme to extract the token from the Authorization header
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Verify if the password matches the hashed password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# Retrieve the user from the "database"
def get_user(db, username: str):
    return db.get(username)


# Authenticate user by verifying username and password
def authenticate_user(username: str, password: str):
    user = get_user(fake_users_db, username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user


# Create a JWT token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Get the current user based on the JWT token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError as e:
        logger.error(f"JWT decode error: {e}")
        raise credentials_exception
    user = get_user(fake_users_db, username)
    if user is None:
        raise credentials_exception
    return user


# Ensure the user is active (not disabled)
async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    if current_user.get("disabled"):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# Hash the password and add the user to the fake database
def create_user(username: str, password: str, full_name: str):
    logger.info(f"Creating user {username}")
    if username in fake_users_db:
        logger.error(f"User {username} already exists")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists",
        )
    hashed_password = pwd_context.hash(password)
    fake_users_db[username] = {
        "username": username,
        "full_name": full_name,
        "email": username,
        "hashed_password": hashed_password,
        "disabled": False,
    }
    logger.info(f"User {username} created successfully")
    return {"username": username, "full_name": full_name}
