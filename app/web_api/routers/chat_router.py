from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException
from typing import List, Dict
from pydantic import BaseModel
import json
import uuid
import logging
import httpx
from datetime import datetime, timezone

from web_api.auth import get_current_active_user

router = APIRouter()
logger = logging.getLogger(__name__)

# Constants
INTENTION_API_URL = "http://intent-api:8000/api/v1/intent"
RAG_API_URL = "http://rag-api:8000/faq/response/"

# These will be set in main.py
conversation_repo = None
message_repo = None
manager = None

# Pydantic model for creating a conversation
class ConversationCreate(BaseModel):
    participants: List[str]

class ConversationResponse(BaseModel):
    conversation_id: str
    participants: List[str]
    last_message: Dict

@router.get("/conversations", response_model=List[ConversationResponse])
async def list_conversations():
    try:
        conversations_list = []
        for conversation_id, conversation in conversation_repo.conversations.items():
            last_message = message_repo.get_messages(conversation_id)[-1] if message_repo.get_messages(conversation_id) else None
            conversations_list.append({
                "conversation_id": conversation_id,
                "participants": conversation.get("participants", []),
                "last_message": last_message
            })
        return conversations_list
    except Exception as e:
        logger.error(f"Error listing conversations: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


# WebSocket endpoint for handling chat conversations
@router.websocket("/ws/chat/{conversation_id}")
async def websocket_endpoint(websocket: WebSocket, conversation_id: str):
    client_id = str(uuid.uuid4())  # Assign a unique ID for each client
    await manager.connect(websocket, client_id)

    try:
        # Check if the conversation exists
        conversation = conversation_repo.get_conversation(conversation_id)
        if not conversation:
            await websocket.close(code=1003)  # Close if conversation doesn't exist
            logger.error(f"Conversation {conversation_id} not found")
            return

        # Add the client to the conversation participants
        conversation_repo.add_participant(conversation_id, client_id)

        # Send the existing chat history to the client
        chat_history = message_repo.get_messages(conversation_id)
        await manager.send_personal_message(json.dumps(chat_history), client_id)

        # Listen for incoming messages
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            logger.info(f"Received message from {client_id}: {message_data}")

            # Add the new message to the conversation, ensuring no duplicates
            response_message_data_from_user = {
                "message": message_data,
                "sender": "client",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            message_repo.add_message(conversation_id, response_message_data_from_user)

            # Broadcast the new message to all participants in the conversation
            await manager.broadcast(json.dumps(message_data), conversation_id)

            # Call external APIs
            try:
                async with httpx.AsyncClient() as client:
                    faq_query = await client.post(
                        INTENTION_API_URL,
                        params={"text": message_data["message"]},
                        timeout=20
                    )

                # Call the FAQ service with the question
                async with httpx.AsyncClient() as client:
                    new_question_with_intent = f'Intenção do usuário: {faq_query.json()["intent_name"]}\n Pergunta:{message_data["message"]}'
                    faq_response = await client.get(
                        RAG_API_URL,
                        params={"question": new_question_with_intent},
                        timeout=40
                    )

                logger.info(f"User intention: {faq_query.json()}")

                if faq_response.status_code == 200:
                    faq_response_data = faq_response.json()
                    response_message = faq_response_data.get("response", "")
                    # Create a message data structure to send back
                    response_message_data = {
                        "message": {
                            "message": response_message,
                            "type": "operator"
                        },
                        "sender": "faq_service",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    # Add the response message to the conversation
                    message_repo.add_message(conversation_id, response_message_data)
                    # Broadcast the response message to all participants
                    await manager.broadcast(json.dumps(response_message_data), conversation_id)
                else:
                    # Handle error if needed
                    logger.error(f"Error from FAQ service: {faq_response.status_code}")
            except Exception as e:
                logger.error(f"Error processing message: {e}")

    except WebSocketDisconnect:
        manager.disconnect(client_id)
        await manager.broadcast(f"Client {client_id} disconnected", conversation_id)

# Route to create a new conversation
@router.post("/conversations/create")
async def create_new_conversation(conversation: ConversationCreate):
    try:
        conversation_id = str(uuid.uuid4())
        conversation_repo.create_conversation(conversation_id, conversation.participants)
        return {"message": "Conversation created", "conversation_id": conversation_id}
    except Exception as e:
        logger.error(f"Error creating conversation: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

# Route to list participants in a conversation
@router.get("/conversations/{conversation_id}/participants")
async def list_participants(conversation_id: str):
    conversation = conversation_repo.get_conversation(conversation_id)
    if not conversation:
        logger.error(f"Conversation {conversation_id} not found")
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"participants": conversation["participants"]}

# Route to list messages in a conversation
@router.get("/conversations/{conversation_id}/messages")
async def list_messages(conversation_id: str):
    messages = message_repo.get_messages(conversation_id)
    if not messages:
        logger.warning(f"No messages found for conversation {conversation_id}")
        raise HTTPException(status_code=404, detail="No messages found for this conversation")
    return {"messages": messages}

# Public routes
@router.get("/")
async def root():
    return {"message": "Hello World"}

@router.get("/hello/{name}")
async def say_hello(name: str, current_user: dict = Depends(get_current_active_user)):
    return {"message": f"Hello {name}, from {current_user['full_name']}"}
