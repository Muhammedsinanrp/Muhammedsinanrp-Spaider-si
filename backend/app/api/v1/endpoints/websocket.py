"""JWT-authenticated WebSocket endpoint for real-time SPAIDER events."""

import uuid
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sqlalchemy import select

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.websocket_manager import ws_manager
from app.models.models import User

router = APIRouter()


@router.websocket("/events")
async def websocket_events(websocket: WebSocket, room: str = "global"):
    """Reject unauthenticated WebSocket connections before joining event rooms."""
    token = websocket.query_params.get("token", "")
    if not token:
        await websocket.close(code=1008, reason="Authentication token required.")
        return

    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id = str(payload.get("sub") or "")
        if not user_id:
            raise JWTError("Missing subject")
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if user is None or not user.is_active:
                await websocket.close(code=1008, reason="Authentication required.")
                return
    except JWTError:
        await websocket.close(code=1008, reason="Invalid or expired authentication token.")
        return
    except Exception:
        await websocket.close(code=1011, reason="Unable to validate authentication.")
        return

    client_id = str(uuid.uuid4())
    await ws_manager.connect(websocket, client_id, room)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await ws_manager.send_personal(client_id, {"type": "pong"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, client_id, room)
