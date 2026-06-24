import asyncio
import uuid
from datetime import datetime
from typing import Dict, Optional, Any, List, Callable
from fastapi import WebSocket, WebSocketDisconnect
import json


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
    
    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict())


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
            print(f"❌ WebSocket connection failed for {self.session_id}: {e}")
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
            print(f"❌ Error sending message to {self.session_id}: {e}")
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


class TaskProgress:
    """Tracks progress for a specific task"""
    
    def __init__(self, task_id: str, task_name: str, total_steps: int = 100):
        self.task_id = task_id
        self.task_name = task_name
        self.total_steps = total_steps
        self.current_step = 0
        self.current_progress = 0
        self.status = "started"
        self.start_time = datetime.now()
        self.end_time = None
        self.messages: List[ProgressMessage] = []
        self.metadata = {}
    
    def update_progress(self, step: int = None, progress: int = None, 
                       message: str = "", status: str = "info", 
                       data: Dict[str, Any] = None) -> ProgressMessage:
        """Update task progress"""
        if step is not None:
            self.current_step = min(step, self.total_steps)
            self.current_progress = int((self.current_step / self.total_steps) * 100)
        elif progress is not None:
            self.current_progress = max(0, min(100, progress))
            self.current_step = int((self.current_progress / 100) * self.total_steps)
        
        if status in ["completed", "success"]:
            self.current_progress = 100
            self.status = "completed"
            self.end_time = datetime.now()
        elif status in ["failed", "error"]:
            self.status = "failed"
            self.end_time = datetime.now()
        elif status in ["cancelled", "aborted"]:
            self.status = "cancelled" 
            self.end_time = datetime.now()
        else:
            self.status = "running"
        
        progress_msg = ProgressMessage(message, self.current_progress, status, data)
        self.messages.append(progress_msg)
        
        return progress_msg
    
    def get_stats(self) -> Dict[str, Any]:
        """Get task statistics"""
        duration = None
        if self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        else:
            duration = (datetime.now() - self.start_time).total_seconds()
        
        return {
            "task_id": self.task_id,
            "task_name": self.task_name,
            "status": self.status,
            "progress": self.current_progress,
            "step": self.current_step,
            "total_steps": self.total_steps,
            "duration_seconds": duration,
            "message_count": len(self.messages),
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "metadata": self.metadata
        }


class ProgressTracker:
    """Main progress tracking manager for WebSocket sessions and tasks"""
    
    def __init__(self, max_sessions: int = 100, session_timeout: int = 3600):
        self.websockets: Dict[str, WebSocketSession] = {}
        self.pending_messages: Dict[str, List[ProgressMessage]] = {}
        self.tasks: Dict[str, TaskProgress] = {}
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
            print(f"❌ Failed to connect WebSocket {session_id}: {e}")
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
            pending = self.pending_messages.setdefault(session_id, [])
            pending.append(ProgressMessage(message, progress, status, data))
            del pending[:-20]
            return False
        
        session = self.websockets[session_id]
        success = await session.send_text(message, progress, status, data)
        
        # Remove session if disconnected
        if not success and not session.connected:
            self.disconnect(session_id)
        
        return success
    
    async def broadcast_progress(self, message: str, progress: int = 0, 
                                status: str = "info", data: Dict[str, Any] = None,
                                task_filter: str = None) -> int:
        """Broadcast progress to all connected sessions (optionally filtered by task)"""
        sent_count = 0
        disconnected_sessions = []
        
        for session_id, session in self.websockets.items():
            # Apply task filter if specified
            if task_filter and session.task_name != task_filter:
                continue
            
            success = await session.send_text(message, progress, status, data)
            if success:
                sent_count += 1
            elif not session.connected:
                disconnected_sessions.append(session_id)
        
        # Clean up disconnected sessions
        for session_id in disconnected_sessions:
            self.disconnect(session_id)
        
        return sent_count
    
    def create_task(self, task_id: str, task_name: str, 
                   total_steps: int = 100) -> TaskProgress:
        """Create a new task for progress tracking"""
        task = TaskProgress(task_id, task_name, total_steps)
        self.tasks[task_id] = task
        return task
    
    async def update_task_progress(self, task_id: str, step: int = None, 
                                  progress: int = None, message: str = "",
                                  status: str = "info", data: Dict[str, Any] = None,
                                  broadcast_to_session: str = None) -> bool:
        """Update task progress and optionally send to WebSocket"""
        if task_id not in self.tasks:
            print(f"⚠️ Task not found: {task_id}")
            return False
        
        task = self.tasks[task_id]
        progress_msg = task.update_progress(step, progress, message, status, data)
        
        # Send to specific session if specified
        if broadcast_to_session:
            await self.send_progress(
                broadcast_to_session,
                progress_msg.message,
                progress_msg.progress,
                progress_msg.status,
                progress_msg.data
            )
        
        return True
    
    def get_task_stats(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific task"""
        if task_id not in self.tasks:
            return None
        return self.tasks[task_id].get_stats()
    
    def get_session_stats(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific session"""
        if session_id not in self.websockets:
            return None
        return self.websockets[session_id].get_stats()
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get statistics for all sessions and tasks"""
        return {
            "sessions": {sid: session.get_stats() for sid, session in self.websockets.items()},
            "tasks": {tid: task.get_stats() for tid, task in self.tasks.items()},
            "summary": {
                "active_sessions": len(self.websockets),
                "total_tasks": len(self.tasks),
                "completed_tasks": sum(1 for task in self.tasks.values() if task.status == "completed"),
                "failed_tasks": sum(1 for task in self.tasks.values() if task.status == "failed"),
                "running_tasks": sum(1 for task in self.tasks.values() if task.status == "running")
            }
        }
    
    async def _cleanup_old_sessions(self):
        """Clean up old/inactive sessions"""
        now = datetime.now()
        to_remove = []
        
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
        
        # Also clean up old completed tasks (keep last 50)
        if len(self.tasks) > 50:
            completed_tasks = [
                (tid, task) for tid, task in self.tasks.items() 
                if task.status in ["completed", "failed", "cancelled"]
            ]
            completed_tasks.sort(key=lambda x: x[1].start_time)
            
            # Remove oldest completed tasks
            for tid, _ in completed_tasks[:-25]:  # Keep last 25 completed
                del self.tasks[tid]
    
    async def start_cleanup_task(self, cleanup_interval: int = 300):
        """Start background cleanup task"""
        async def cleanup_loop():
            while True:
                await asyncio.sleep(cleanup_interval)
                await self._cleanup_old_sessions()
        
        self._cleanup_task = asyncio.create_task(cleanup_loop())
    
    def stop_cleanup_task(self):
        """Stop background cleanup task"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            self._cleanup_task = None


# Utility functions for common progress patterns
async def track_progress_steps(tracker: ProgressTracker, session_id: str, 
                              steps: List[Callable], step_names: List[str] = None) -> bool:
    """Execute a series of steps with automatic progress tracking"""
    total_steps = len(steps)
    step_names = step_names or [f"Step {i+1}" for i in range(total_steps)]
    
    try:
        for i, (step_func, step_name) in enumerate(zip(steps, step_names)):
            progress = int((i / total_steps) * 100)
            await tracker.send_progress(
                session_id, 
                f"🔄 {step_name}...", 
                progress, 
                "info"
            )
            
            # Execute step
            result = await step_func() if asyncio.iscoroutinefunction(step_func) else step_func()
            
            # Check if step failed
            if result is False:
                await tracker.send_progress(
                    session_id,
                    f"❌ {step_name} failed",
                    progress,
                    "error"
                )
                return False
        
        # Completion
        await tracker.send_progress(
            session_id,
            "✅ All steps completed successfully!",
            100,
            "success"
        )
        return True
        
    except Exception as e:
        await tracker.send_progress(
            session_id,
            f"❌ Error during execution: {str(e)}",
            0,
            "error"
        )
        return False


def generate_session_id() -> str:
    """Generate a unique session ID"""
    return str(uuid.uuid4())
