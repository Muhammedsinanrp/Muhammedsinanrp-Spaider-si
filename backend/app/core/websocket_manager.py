"""WebSocket connection manager for real-time SPAIDER events."""

from typing import Dict, Set
from fastapi import WebSocket
import json
import structlog

logger = structlog.get_logger(__name__)


class WebSocketManager:
    def __init__(self):
        # room_id -> set of WebSocket connections
        self.rooms: Dict[str, Set[WebSocket]] = {}
        # client_id -> WebSocket
        self.clients: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, client_id: str, room: str = "global"):
        await websocket.accept()
        self.clients[client_id] = websocket
        if room not in self.rooms:
            self.rooms[room] = set()
        self.rooms[room].add(websocket)
        logger.info("WebSocket connected", client_id=client_id, room=room)

    def disconnect(self, websocket: WebSocket, client_id: str, room: str = "global"):
        self.clients.pop(client_id, None)
        if room in self.rooms:
            self.rooms[room].discard(websocket)
        logger.info("WebSocket disconnected", client_id=client_id)

    async def broadcast(self, event: dict, room: str = "global"):
        """Broadcast an event to all clients in a room."""
        if room not in self.rooms:
            return
        dead = set()
        for ws in self.rooms[room]:
            try:
                await ws.send_text(json.dumps(event))
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.rooms[room].discard(ws)

    async def send_personal(self, client_id: str, event: dict):
        """Send an event to a specific client."""
        ws = self.clients.get(client_id)
        if ws:
            try:
                await ws.send_text(json.dumps(event))
            except Exception:
                self.clients.pop(client_id, None)

    async def emit(self, event_type: str, data: dict, room: str = "global"):
        """Emit a typed event to a room."""
        await self.broadcast({"type": event_type, "data": data}, room)


ws_manager = WebSocketManager()
