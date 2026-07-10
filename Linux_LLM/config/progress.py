import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, List
from fastapi import WebSocket, WebSocketDisconnect


class ProgressMessage:
    """Represents a progress update message"""
    
    def __init__(self, message: str, progress: int = 0, 
                 status: str = "info", data: Dict[str, Any] = None):
        self.message = message
        self.progress = max(0, min(100, progress))  # Clamp between 0-100
        self.status = status  # info, success, warning, error
        self.timestamp = datetime.now()
        self.data = data or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "message": self.message,
            "progress": self.progress,
            "status": self.status,
            "timestamp": self.timestamp.strftime("%H:%M:%S"),
            "iso_timestamp": self.timestamp.isoformat(),
            "data": self.data
        }
    
class WebSocketSession:
    """Manages a single WebSocket session for progress tracking"""
    
    def __init__(self, session_id: str, websocket: WebSocket):
        self.session_id = session_id
        self.websocket = websocket
        self.connected = False
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.message_count = 0
        self.task_name = ""
        self.metadata = {}
    
    async def connect(self):
        """Accept WebSocket connection"""
        try:
            self.connected = True
            self.last_activity = datetime.now()
            return True
        except Exception as e:
            print(f"WebSocket connection failed ({type(e).__name__})")
            return False
    
    async def send_message(self, progress_msg: ProgressMessage) -> bool:
        """Send progress message to WebSocket"""
        if not self.connected:
            return False
        
        try:
            await self.websocket.send_json(progress_msg.to_dict())
            self.last_activity = datetime.now()
            self.message_count += 1
            return True
        except WebSocketDisconnect:
            print(f"🔌 WebSocket disconnected: {self.session_id}")
            self.connected = False
            return False
        except Exception as e:
            print(f"WebSocket progress send failed ({type(e).__name__})")
            self.connected = False
            return False
    
    async def send_text(self, message: str, progress: int = 0, 
                       status: str = "info", data: Dict[str, Any] = None) -> bool:
        """Send a simple text message"""
        progress_msg = ProgressMessage(message, progress, status, data)
        return await self.send_message(progress_msg)
    
    def disconnect(self):
        """Mark session as disconnected"""
        self.connected = False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        duration = (datetime.now() - self.created_at).total_seconds()
        idle_time = (datetime.now() - self.last_activity).total_seconds()
        
        return {
            "session_id": self.session_id,
            "connected": self.connected,
            "duration_seconds": duration,
            "idle_seconds": idle_time,
            "message_count": self.message_count,
            "task_name": self.task_name,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "metadata": self.metadata
        }


class ProgressTracker:
    """Progress tracking manager for authenticated WebSocket sessions."""

    MAX_PENDING_MESSAGES_PER_SESSION = 20
    
    def __init__(self, max_sessions: int = 100, session_timeout: int = 3600):
        self.websockets: Dict[str, WebSocketSession] = {}
        self.pending_messages: Dict[str, List[ProgressMessage]] = {}
        self.max_sessions = max_sessions
        self.session_timeout = session_timeout
        self._cleanup_task = None
    
    async def connect(self, session_id: str, websocket: WebSocket, 
                     task_name: str = "") -> bool:
        """Connect a new WebSocket session"""
        try:
            if not self._is_valid_session_id(session_id):
                print(f"Rejected WebSocket connection with invalid session id: {session_id}")
                return False

            # Clean up old sessions if needed
            await self._cleanup_old_sessions()

            if session_id not in self.websockets and len(self.websockets) >= self.max_sessions:
                print(f"Rejected WebSocket connection; max sessions reached ({self.max_sessions})")
                return False
            
            # Create new session
            session = WebSocketSession(session_id, websocket)
            
            if await session.connect():
                session.task_name = task_name
                self.websockets[session_id] = session
                
                # Send welcome message
                await session.send_text(
                    f"🔗 Connected to progress tracker for task: {task_name or 'Unknown'}",
                    progress=0,
                    status="success",
                    data={"session_id": session_id, "task_name": task_name}
                )

                pending_messages = self.pending_messages.pop(session_id, [])
                for progress_msg in pending_messages:
                    await session.send_message(progress_msg)
                
                print(f"✅ WebSocket connected: {session_id} (task: {task_name})")
                return True
            else:
                return False
        except Exception as e:
            print(f"WebSocket setup failed ({type(e).__name__})")
            return False

    @staticmethod
    def _is_valid_session_id(session_id: str) -> bool:
        try:
            return str(uuid.UUID(str(session_id))) == str(session_id)
        except (TypeError, ValueError, AttributeError):
            return False
    
    def disconnect(self, session_id: str):
        """Disconnect a WebSocket session"""
        if session_id in self.websockets:
            self.websockets[session_id].disconnect()
            del self.websockets[session_id]
            print(f"🔌 WebSocket disconnected: {session_id}")
    
    async def send_progress(self, session_id: str, message: str, 
                           progress: int = 0, status: str = "info", 
                           data: Dict[str, Any] = None) -> bool:
        """Send progress update to a specific session"""
        if session_id not in self.websockets:
            progress_message = ProgressMessage(message, progress, status, data)
            self._cleanup_stale_pending_messages(progress_message.timestamp)

            if session_id not in self.pending_messages:
                if self.max_sessions <= 0:
                    return False
                self._make_pending_session_room()

            pending = self.pending_messages.setdefault(session_id, [])
            pending.append(progress_message)
            del pending[:-self.MAX_PENDING_MESSAGES_PER_SESSION]
            return False
        
        session = self.websockets[session_id]
        success = await session.send_text(message, progress, status, data)
        
        # Remove session if disconnected
        if not success and not session.connected:
            self.disconnect(session_id)
        
        return success

    @staticmethod
    def _pending_last_activity(messages: List[ProgressMessage]) -> datetime:
        """Return the newest timestamp in a pending message collection."""
        return max((message.timestamp for message in messages), default=datetime.min)

    def _cleanup_stale_pending_messages(self, now: datetime = None):
        """Expire disconnected pending sessions after the inactivity timeout."""
        now = now or datetime.now()
        stale_session_ids = [
            session_id
            for session_id, messages in self.pending_messages.items()
            if not messages
            or (
                now - self._pending_last_activity(messages)
            ).total_seconds() > self.session_timeout
        ]
        for session_id in stale_session_ids:
            self.pending_messages.pop(session_id, None)

    def _make_pending_session_room(self):
        """Evict least-recently-active pending sessions to enforce the key cap."""
        while len(self.pending_messages) >= self.max_sessions:
            oldest_session_id = min(
                self.pending_messages,
                key=lambda session_id: (
                    self._pending_last_activity(self.pending_messages[session_id]),
                    session_id,
                ),
            )
            self.pending_messages.pop(oldest_session_id, None)
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get statistics for connected progress sessions."""
        return {
            "sessions": {sid: session.get_stats() for sid, session in self.websockets.items()},
            "summary": {
                "active_sessions": len(self.websockets),
            }
        }
    
    async def _cleanup_old_sessions(self):
        """Clean up old/inactive sessions"""
        now = datetime.now()
        to_remove = []

        self._cleanup_stale_pending_messages(now)
        
        for session_id, session in self.websockets.items():
            # Remove if not connected
            if not session.connected:
                to_remove.append(session_id)
                continue
            
            # Remove if idle for too long
            idle_time = (now - session.last_activity).total_seconds()
            if idle_time > self.session_timeout:
                to_remove.append(session_id)
                continue
        
        for session_id in to_remove:
            print(f"🧹 Cleaning up inactive session: {session_id}")
            self.disconnect(session_id)
        
    
    async def start_cleanup_task(self, cleanup_interval: int = 300):
        """Start background cleanup task"""
        if self._cleanup_task is not None and not self._cleanup_task.done():
            return

        async def cleanup_loop():
            while True:
                await asyncio.sleep(cleanup_interval)
                await self._cleanup_old_sessions()
        
        self._cleanup_task = asyncio.create_task(cleanup_loop())
    
    async def stop_cleanup_task(self):
        """Stop background cleanup task"""
        if self._cleanup_task:
            task = self._cleanup_task
            self._cleanup_task = None
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

def generate_session_id() -> str:
    """Generate a unique session ID"""
    return str(uuid.uuid4())
