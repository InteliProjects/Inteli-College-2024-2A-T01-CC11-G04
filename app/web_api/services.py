# services.py
import logging
from typing import List, Dict, Optional

from fastapi import WebSocket

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# In-memory repositories for conversations and messages
class ConversationRepository:
    def __init__(self):
        self.conversations: Dict[str, Dict] = {}

    def create_conversation(self, conversation_id: str, participants: List[str]):
        self.conversations[conversation_id] = {
            "participants": participants,
            "messages": []
        }
        logger.info(f"Conversation {conversation_id} created with participants {participants}")

    def get_conversation(self, conversation_id: str) -> Optional[Dict]:
        return self.conversations.get(conversation_id)

    def add_participant(self, conversation_id: str, participant: str):
        if conversation_id in self.conversations:
            self.conversations[conversation_id]["participants"].append(participant)
            logger.info(f"Participant {participant} added to conversation {conversation_id}")

    def is_participant(self, conversation_id: str, participant: str) -> bool:
        conversation = self.get_conversation(conversation_id)
        return conversation and participant in conversation["participants"]


class MessageRepository:
    def __init__(self):
        self.messages: Dict[str, List[Dict]] = {}

    def add_message(self, conversation_id: str, message_data: Dict):
        if conversation_id not in self.messages:
            self.messages[conversation_id] = []
        if message_data not in self.messages[conversation_id]:
            self.messages[conversation_id].append(message_data)
            logger.info(f"Message added to conversation {conversation_id}: {message_data}")

    def get_messages(self, conversation_id: str) -> List[Dict]:
        return self.messages.get(conversation_id, [])


# Connection Manager to manage WebSocket connections
class ConnectionManager:
    def __init__(self, conversation_repo: ConversationRepository):
        self.active_connections: Dict[str, WebSocket] = {}
        self.conversation_repo = conversation_repo

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"Client {client_id} connected")

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            logger.info(f"Client {client_id} disconnected")

    async def send_personal_message(self, message: str, client_id: str):
        if client_id in self.active_connections:
            websocket = self.active_connections[client_id]
            await websocket.send_text(message)
            logger.info(f"Sent personal message to {client_id}: {message}")

    async def broadcast(self, message: str, conversation_id: str):
        conversation = self.conversation_repo.get_conversation(conversation_id)
        if conversation:
            participants = conversation["participants"]
            for participant in participants:
                if participant in self.active_connections:
                    websocket = self.active_connections[participant]
                    await websocket.send_text(message)
            logger.info(f"Broadcasted message in conversation {conversation_id}: {message}")
