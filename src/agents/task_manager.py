from typing import Dict, List, Any, Optional, Union
import asyncio
from datetime import datetime
from pydantic import BaseModel, Field
from ..utils.logger import logger
from ..config.settings import settings

class TaskStatus:
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"

class Task(BaseModel):
    """Model representing a security testing task."""
    id: str = Field(default_factory=lambda: datetime.now().isoformat())
    tool: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    priority: int = 3
    depends_on: List[str] = Field(default_factory=list)
    status: str = TaskStatus.PENDING
    attempt: int = 1
    max_attempts: int = settings.MAX_RETRIES
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

class TaskManager:
    def __init__(self):
        """Initialize the task manager."""
        self.tasks: Dict[str, Task] = {}
        self.running_tasks: Dict[str, asyncio.Task] = {}
        self.max_concurrent_tasks: int = 5
        self.task_semaphore = asyncio.Semaphore(self.max_concurrent_tasks)
        
    def add_task(self, task: Union[Task, Dict[str, Any]]) -> Task:
        """Add a new task to the manager."""
        if isinstance(task, dict):
            task = Task(**task)
            
        self.tasks[task.id] = task
        logger.info(f"Added task {task.id} ({task.tool} on {task.target})")
        return task
        
    def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by ID."""
        return self.tasks.get(task_id)
        
    def get_tasks_by_status(self, status: str) -> List[Task]:
        """Get all tasks with a specific status."""
        return [task for task in self.tasks.values() if task.status == status]
        
    def get_executable_tasks(self) -> List[Task]:
        """Get tasks that are ready to be executed (dependencies satisfied)."""
        executable = []
        for task in self.tasks.values():
            if task.status != TaskStatus.PENDING:
                continue
                
            # Check if all dependencies are completed
            deps_satisfied = all(
                self.tasks[dep].status == TaskStatus.COMPLETED
                for dep in task.depends_on
                if dep in self.tasks
            )
            
            if deps_satisfied:
                executable.append(task)
                
        # Sort by priority
        executable.sort(key=lambda x: x.priority)
        return executable
        
    async def execute_task(self, task: Task, tool_executor: Any) -> None:
        """Execute a single task with retries."""
        async with self.task_semaphore:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now()
            
            try:
                logger.info(f"Executing task {task.id} ({task.tool} on {task.target})")
                
                # Execute the task
                result = await tool_executor.ainvoke({
                    "name": task.tool,
                    "arguments": {
                        "target": task.target,
                        **task.parameters
                    }
                })
                
                # Update task status
                task.status = TaskStatus.COMPLETED
                task.result = result
                task.completed_at = datetime.now()
                logger.info(f"Task {task.id} completed successfully")
                
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Task {task.id} failed: {error_msg}")
                
                # Handle retry
                if task.attempt < task.max_attempts:
                    task.attempt += 1
                    task.status = TaskStatus.RETRYING
                    task.error = error_msg
                    logger.info(f"Scheduling retry {task.attempt}/{task.max_attempts} for task {task.id}")
                    
                    # Add delay before retry
                    await asyncio.sleep(settings.RETRY_DELAY)
                    await self.execute_task(task, tool_executor)
                else:
                    task.status = TaskStatus.FAILED
                    task.error = error_msg
                    task.completed_at = datetime.now()
                    logger.error(f"Task {task.id} failed permanently after {task.attempt} attempts")
                    
    async def run_tasks(self, tool_executor: Any) -> None:
        """Run all executable tasks concurrently."""
        while True:
            executable_tasks = self.get_executable_tasks()
            if not executable_tasks:
                # Check if any tasks are still running
                if not self.running_tasks:
                    break
                await asyncio.sleep(1)
                continue
                
            # Start new tasks
            for task in executable_tasks:
                if task.id not in self.running_tasks:
                    self.running_tasks[task.id] = asyncio.create_task(
                        self.execute_task(task, tool_executor)
                    )
                    
            # Clean up completed tasks
            done_tasks = []
            for task_id, task_obj in self.running_tasks.items():
                if task_obj.done():
                    done_tasks.append(task_id)
                    try:
                        await task_obj
                    except Exception as e:
                        logger.error(f"Task {task_id} failed: {str(e)}")
                        
            for task_id in done_tasks:
                del self.running_tasks[task_id]
                
            await asyncio.sleep(0.1)
            
    def get_results(self) -> Dict[str, Any]:
        """Get results of all completed tasks."""
        return {
            task_id: {
                "tool": task.tool,
                "target": task.target,
                "status": task.status,
                "result": task.result,
                "error": task.error,
                "attempts": task.attempt,
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "completed_at": task.completed_at.isoformat() if task.completed_at else None
            }
            for task_id, task in self.tasks.items()
        }
        
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of task execution."""
        total = len(self.tasks)
        completed = len([t for t in self.tasks.values() if t.status == TaskStatus.COMPLETED])
        failed = len([t for t in self.tasks.values() if t.status == TaskStatus.FAILED])
        pending = len([t for t in self.tasks.values() if t.status == TaskStatus.PENDING])
        running = len([t for t in self.tasks.values() if t.status == TaskStatus.RUNNING])
        
        return {
            "total_tasks": total,
            "completed": completed,
            "failed": failed,
            "pending": pending,
            "running": running,
            "success_rate": (completed / total * 100) if total > 0 else 0
        }

# Create singleton instance
task_manager = TaskManager()
