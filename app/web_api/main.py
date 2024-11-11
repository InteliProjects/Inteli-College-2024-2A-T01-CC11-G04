import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .auth import create_user
from .services import ConversationRepository, MessageRepository, ConnectionManager
from .routers import auth_router, chat_router

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Allow all CORS origins, methods, and headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize repositories and manager
conversation_repo = ConversationRepository()
message_repo = MessageRepository()
manager = ConnectionManager(conversation_repo)

# Pass the repositories and manager to the routers
chat_router.conversation_repo = conversation_repo
chat_router.message_repo = message_repo
chat_router.manager = manager

# Include routers
app.include_router(auth_router.router)
app.include_router(chat_router.router)

# Create a default user
create_user(full_name="Brastel", username="brastel@brastel.com", password="123456")
