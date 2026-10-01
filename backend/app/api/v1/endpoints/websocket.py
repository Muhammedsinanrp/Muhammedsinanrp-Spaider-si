"""WebSocket endpoint for real-time SPAIDER events."""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.websocket_manager import ws_manager
import uuid

router = APIRouter()


@router.websocket("/events")
async def websocket_events(websocket: WebSocket, room: str = "global"):
    """Main WebSocket channel for real-time events."""
    client_id = str(uuid.uuid4())
    await ws_manager.connect(websocket, client_id, room)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo ping/pong
            if data == "ping":
                await ws_manager.send_personal(client_id, {"type": "pong"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, client_id, room)
