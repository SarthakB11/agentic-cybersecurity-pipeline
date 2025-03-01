from typing import Dict, List, Any, Optional, TypedDict, Annotated, Callable
import asyncio
import os
import json
import aiohttp
from pydantic import BaseModel, Field, ConfigDict
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.output_parsers import JsonOutputParser
from langchain.tools.base import BaseTool
from langgraph.graph import Graph, END
from langgraph.checkpoint.memory import MemorySaver
from operator import itemgetter
from datetime import datetime
from langgraph.errors import GraphRecursionError
import uuid

from ..config.settings import settings
from ..utils.logger import logger
from ..utils.scope_validator import scope_validator, ScopeValidator
from ..tools.nmap_tool import nmap_tool
from ..tools.gobuster_tool import gobuster_tool
from ..tools.ffuf_tool import ffuf_tool
from ..tools.sqlmap_tool import sqlmap_tool

# Set Google API key environment variable
os.environ["GOOGLE_API_KEY"] = settings.GEMINI_API_KEY

class AgentState(TypedDict):
    """Type definition for agent state."""
    messages: List[Any]  # List of messages in the conversation
    task_list: List[Dict[str, Any]]  # List of tasks to be executed
    current_task: Optional[Dict[str, Any]]  # Currently executing task
    results: Dict[str, Dict[str, Any]]  # Results from executed tasks, keyed by task ID
    errors: List[str]  # List of errors encountered
    retry_count: Dict[str, int]  # Count of retries per task
    completed_tasks: List[Dict[str, Any]]  # List of completed tasks with results
    iteration_count: int  # Count of workflow iterations
    target: str  # Target being audited
    scope: Dict[str, Any]  # Scope configuration
    should_continue: bool  # Flag to control workflow continuation
    logs: List[Dict[str, Any]]  # Audit logs with timestamps and actions
    
    model_config = ConfigDict(arbitrary_types_allowed=True)

class GeminiAPI:
    """Wrapper for Gemini API calls with rate limiting."""
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"
        self.model = "gemini-pro"
        self.retry_delay = 2  # seconds
        self.max_retries = 3
        
    async def generate_content(self, prompt: str) -> str:
        """Make an async call to Gemini API with retries."""
        url = f"{self.base_url}/{self.model}:generateContent?key={self.api_key}"
        
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }
        
        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, json=payload) as response:
                        if response.status == 200:
                            data = await response.json()
                            return data["candidates"][0]["content"]["parts"][0]["text"]
                        elif response.status == 429:  # Rate limit
                            error_msg = "Quota exceeded for quota metric 'Generate Content API requests per minute'"
                            logger.warning(f"Rate limit hit: {error_msg}")
                            if attempt == self.max_retries - 1:
                                raise RuntimeError(error_msg)
                            await asyncio.sleep(self.retry_delay * (attempt + 1))
                            continue
                        else:
                            error_data = await response.text()
                            raise RuntimeError(f"Gemini API error: {error_data}")
            except Exception as e:
                if attempt == self.max_retries - 1:
                    logger.error(f"Error calling Gemini API: {str(e)}")
                    raise
                await asyncio.sleep(self.retry_delay * (attempt + 1))
        
        raise RuntimeError("Max retries exceeded for Gemini API call")

class SecurityAgent:
    def __init__(self):
        """Initialize the security agent with LangGraph components."""
        self.gemini = GeminiAPI(api_key=settings.GEMINI_API_KEY)
        self.max_iterations = 50  # Maximum number of workflow iterations
        self.max_retries = settings.MAX_RETRIES
        
        # Set up tools
        self.tools = {
            "nmap_scan": nmap_tool.run,
            "directory_scan": gobuster_tool.run,
            "fuzzing_scan": ffuf_tool.run,
            "sql_injection_scan": sqlmap_tool.run
        }
        
        # Set up the task planning prompt
        self.task_planning_prompt = """You are a security testing assistant. Based on the current state and results,
        determine the next security testing tasks to perform. Tasks should be ordered by priority and dependency.
        
        Target: {target}
        Scope:
        - Allowed Domains: {allowed_domains}
        - Allowed IPs: {allowed_ips}
        - Excluded Paths: {excluded_paths}
        
        Completed Tasks:
        {completed_tasks}
        
        Current Results:
        {results}
        
        Each task should include:
        - tool: The security tool to use (nmap_scan, directory_scan, fuzzing_scan, sql_injection_scan)
        - target: The target URL or IP to scan
        - parameters: Dictionary of tool-specific parameters
        - priority: Task priority (1-5, where 1 is highest)
        - depends_on: List of task IDs this task depends on (or empty list)
        
        Output a JSON list of tasks."""
        
        # Set up the task execution prompt
        self.task_execution_prompt = """You are a security testing assistant. Review the results of the last executed task
        and determine if any additional tasks should be added based on the findings.
        
        Target: {target}
        Scope: {scope}
        
        Last Task Results:
        {results}
        
        Consider:
        - New targets discovered (subdomains, IP addresses)
        - Open ports that require further investigation
        - Potential vulnerabilities that need verification
        - Failed tasks that should be retried with different parameters
        
        Output a JSON object with:
        - new_tasks: List of new tasks to add
        - retry_current: Boolean indicating if current task should be retried
        - retry_parameters: New parameters if task should be retried"""
        
        # Create the workflow graph
        self.workflow = self._create_workflow()
        
    def _create_workflow(self) -> Graph:
        """Create the LangGraph workflow for security testing."""
        # Create workflow
        workflow = Graph()
        
        # Define the nodes
        workflow.add_node("plan", self._plan_tasks)
        workflow.add_node("execute", self._execute_task)
        workflow.add_node("process", self._process_results)
        
        # Add edges
        workflow.add_edge("plan", "execute")
        workflow.add_edge("execute", "process")
        workflow.add_edge("process", "plan")
        
        # Set entry point
        workflow.set_entry_point("plan")
        
        # Add conditional edges
        def should_continue(state: AgentState) -> bool:
            """Check if workflow should continue."""
            # Stop if we've hit the iteration limit
            if state["iteration_count"] >= self.max_iterations:
                error_msg = f"Maximum iterations ({self.max_iterations}) reached without completion"
                state["errors"].append(error_msg)
                return False
                
            # Stop if we've encountered a critical error
            if any("quota exceeded" in str(error).lower() for error in state["errors"]):
                return False
                
            # Continue if we have tasks
            if state["task_list"]:
                return True
                
            # Continue if we have a current task
            if state["current_task"]:
                return True
                
            # Stop if we have completed all tasks
            if state["completed_tasks"]:
                return False
                
            # Continue by default to allow for task planning
            return True
            
        workflow.add_conditional_edges(
            "process",
            should_continue,
            {
                True: "plan",
                False: END
            }
        )
        
        # Compile the graph
        return workflow.compile()
        
    async def _plan_tasks(self, state: AgentState) -> AgentState:
        """Plan the next security testing tasks."""
        try:
            # Check iteration limit
            if state["iteration_count"] >= self.max_iterations:
                error_msg = f"Maximum iterations ({self.max_iterations}) reached without completion"
                logger.warning(error_msg)
                state["errors"].append(error_msg)
                state["should_continue"] = False
                return state
                
            # Skip if there are pending tasks
            if state["task_list"]:
                return state
                
            # If we have completed all tasks and there are no pending tasks, we're done
            if state["completed_tasks"] and not state["task_list"]:
                state["should_continue"] = False
                # Clear any iteration limit errors since we completed successfully
                state["errors"] = [e for e in state["errors"] if "maximum iterations" not in e.lower()]
                return state
                
            try:
                # Format messages for the prompt
                response = await self.gemini.generate_content(
                    self.task_planning_prompt.format(
                        target=state["target"],
                        allowed_domains=", ".join(state["scope"].get("allowed_domains", [])),
                        allowed_ips=", ".join(state["scope"].get("allowed_ips", [])),
                        excluded_paths=", ".join(state["scope"].get("excluded_paths", [])),
                        completed_tasks=", ".join(f"{task['tool']} on {task['target']}" for task in state["completed_tasks"]),
                        results=json.dumps(state["results"])
                    )
                )
                
                # Parse the response
                try:
                    # Handle both string and response object inputs
                    response_text = response.text if hasattr(response, "text") else str(response)
                    # Clean up the response text
                    response_text = response_text.strip()
                    
                    # Try parsing with json first
                    try:
                        new_tasks = json.loads(response_text)
                    except json.JSONDecodeError:
                        # Try parsing with ast.literal_eval for safer string evaluation
                        import ast
                        new_tasks = ast.literal_eval(response_text)
                    
                    # Ensure new_tasks is a list
                    if not isinstance(new_tasks, list):
                        raise ValueError("Expected a list of tasks")
                        
                    # Validate each task
                    for task in new_tasks:
                        if not isinstance(task, dict):
                            raise ValueError("Each task must be a dictionary")
                        required_fields = {"tool", "target", "priority"}
                        if not all(field in task for field in required_fields):
                            raise ValueError(f"Task missing required fields: {required_fields}")
                        
                except (json.JSONDecodeError, ValueError, SyntaxError) as e:
                    logger.error(f"Error parsing task planning response: {str(e)}")
                    # Don't stop the workflow for parsing errors in task planning
                    return state
                
                # Check if we have any tasks
                if not new_tasks:
                    logger.info("No more tasks to execute")
                    state["should_continue"] = False
                    # Clear any iteration limit errors since we completed successfully
                    state["errors"] = [e for e in state["errors"] if "maximum iterations" not in e.lower()]
                    return state
                
                # Update task list
                state["task_list"].extend(new_tasks)
                
                # Sort tasks by priority and dependencies
                state["task_list"].sort(key=lambda x: (x["priority"], len(x.get("depends_on", []))))
                
                # Increment iteration count
                state["iteration_count"] += 1
                
                logger.info(f"Planned {len(new_tasks)} new tasks")
                return state
                
            except RuntimeError as e:
                if "quota exceeded" in str(e).lower():
                    logger.error(f"Rate limit error: {str(e)}")
                    state["errors"].append(str(e))
                    state["should_continue"] = False
                    return state
                raise
                
        except Exception as e:
            logger.error(f"Error in task planning: {str(e)}")
            # Don't stop the workflow for general errors in task planning
            return state
            
    async def _execute_task(self, state: AgentState) -> AgentState:
        """Execute the current task."""
        try:
            # Skip if no tasks
            if not state["task_list"]:
                return state
            
            # Get next task from list if no current task
            if not state["current_task"]:
                next_task = state["task_list"].pop(0)
                next_task["id"] = str(uuid.uuid4())
                state["current_task"] = next_task
            
            current_task = state["current_task"]
            task_id = current_task["id"]
            tool_name = current_task["tool"]
            target = current_task["target"]
            parameters = current_task.get("parameters", {})
            
            # Check if tool exists
            if tool_name not in self.tools:
                error_msg = f"Unknown tool: {tool_name}"
                logger.error(error_msg)
                state["errors"].append(error_msg)
                state["results"][task_id] = {
                    "tool": tool_name,
                    "target": target,
                    "parameters": parameters,
                    "status": "failed",
                    "error": error_msg,
                    "started_at": datetime.now().isoformat(),
                    "completed_at": datetime.now().isoformat()
                }
                state["completed_tasks"].append(task_id)
                state["current_task"] = None
                return state
            
            # Execute tool
            logger.info(f"Executing {tool_name} on {target}")
            try:
                started_at = datetime.now().isoformat()
                result = await self.tools[tool_name](target, **parameters)
                completed_at = datetime.now().isoformat()
                
                # Store successful result
                state["results"][task_id] = {
                    "tool": tool_name,
                    "target": target,
                    "parameters": parameters,
                    "status": "completed",
                    "result": result,
                    "started_at": started_at,
                    "completed_at": completed_at
                }
                state["completed_tasks"].append(task_id)
                state["current_task"] = None
                
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Error executing task: {error_msg}")
                state["errors"].append(error_msg)
                
                # Get retry count for this task signature
                task_signature = f"{tool_name}_{target}"
                retry_count = state["retry_count"].get(task_signature, 0)
                
                if retry_count < self.max_retries:
                    # Increment retry count
                    state["retry_count"][task_signature] = retry_count + 1
                    logger.info(f"Retrying task (attempt {retry_count + 1})")
                    
                    # Store result with retry status
                    state["results"][task_id] = {
                        "tool": tool_name,
                        "target": target,
                        "parameters": parameters,
                        "status": "retrying",
                        "error": error_msg,
                        "retry_count": retry_count + 1,
                        "started_at": datetime.now().isoformat(),
                        "completed_at": datetime.now().isoformat()
                    }
                    
                    # Create retry task with same signature but new ID
                    retry_task = current_task.copy()
                    retry_task["id"] = str(uuid.uuid4())
                    retry_task["original_task_id"] = task_id  # Track original task
                    state["task_list"].append(retry_task)
                    state["current_task"] = None
                    
                else:
                    # Mark as failed after max retries
                    state["results"][task_id] = {
                        "tool": tool_name,
                        "target": target,
                        "parameters": parameters,
                        "status": "failed",
                        "error": error_msg,
                        "retry_count": retry_count,
                        "started_at": datetime.now().isoformat(),
                        "completed_at": datetime.now().isoformat()
                    }
                    state["completed_tasks"].append(task_id)
                    state["current_task"] = None
                
        except Exception as e:
            error_msg = f"Error in task execution: {str(e)}"
            logger.error(error_msg)
            state["errors"].append(error_msg)
            state["current_task"] = None
        
        return state
        
    async def _process_results(self, state: AgentState) -> AgentState:
        """Process task results and update task list."""
        try:
            # Get latest result
            latest_task_id = state["current_task"]["id"] if state["current_task"] else None
            if not latest_task_id or latest_task_id not in state["results"]:
                return state
            
            latest_result = state["results"][latest_task_id]
            
            # Skip if task is still retrying
            if latest_result["status"] == "retrying":
                return state
            
            # If this is a retry task, update the original task's result
            if "original_task_id" in state["current_task"]:
                original_task_id = state["current_task"]["original_task_id"]
                if latest_result["status"] == "completed":
                    # Copy successful result to original task
                    state["results"][original_task_id] = latest_result.copy()
                    state["results"][original_task_id]["id"] = original_task_id
                    state["completed_tasks"].append(original_task_id)
                    # Remove retry result to avoid double counting
                    del state["results"][latest_task_id]
                return state
            
            try:
                # Get task execution decision from Gemini
                prompt = self._create_task_execution_prompt(state)
                response = await self.gemini.generate_content(prompt)
                
                try:
                    decision = json.loads(response)
                    
                    # Process new tasks
                    new_tasks = decision.get("new_tasks", [])
                    for task in new_tasks:
                        if not isinstance(task, dict):
                            continue
                            
                        required_fields = ["tool", "target", "parameters", "priority"]
                        if not all(field in task for field in required_fields):
                            continue
                            
                        # Validate target is in scope
                        if not await self.scope_validator.validate_target(task["target"]):
                            continue
                            
                        # Check if this task is already in results or task list
                        task_signature = f"{task['tool']}_{task['target']}"
                        is_duplicate = any(
                            f"{r['tool']}_{r['target']}" == task_signature
                            for r in state["results"].values()
                        ) or any(
                            f"{t['tool']}_{t['target']}" == task_signature
                            for t in state["task_list"]
                        )
                        
                        if not is_duplicate:
                            task["id"] = str(uuid.uuid4())
                            state["task_list"].append(task)
                            
                    logger.info(f"Added {len(new_tasks)} new tasks based on results")
                    
                except (json.JSONDecodeError, ValueError, SyntaxError) as e:
                    error_msg = f"Error parsing task execution response: {str(e)}"
                    logger.error(error_msg)
                    
            except Exception as e:
                error_msg = f"Error processing results: {str(e)}"
                logger.error(error_msg)
                state["errors"].append(error_msg)
                
        except Exception as e:
            error_msg = f"Error in result processing: {str(e)}"
            logger.error(error_msg)
            state["errors"].append(error_msg)
            
        return state
            
    async def run_security_audit(self, target: str, scope: dict) -> dict:
        """Run a security audit on the target."""
        try:
            # Initialize state
            state = {
                "target": target,
                "scope": scope,
                "task_list": [],
                "current_task": None,
                "results": {},
                "errors": [],
                "completed_tasks": [],
                "logs": [],
                "retry_count": {},
                "iteration_count": 0,
                "should_continue": True
            }
            
            # Set up scope validator
            self.scope_validator = ScopeValidator()
            self.scope_validator.update_scope(scope)
            
            # Configure workflow
            config = {
                "recursion_limit": self.max_iterations + 1,  # Add 1 to account for initial state
                "configurable": {
                    "thread_id": str(id(state)),
                    "checkpoint_ns": "security_audit",
                    "checkpoint_id": f"{target}_{datetime.now().isoformat()}"
                },
                "run_name": f"security_audit_{target}",
                "metadata": {
                    "target": target,
                    "scope": scope
                }
            }
            
            # Run the workflow
            try:
                final_state = await self.workflow.ainvoke(state, config=config)
            except GraphRecursionError:
                # Handle recursion limit gracefully
                error_msg = f"Maximum iterations ({self.max_iterations}) reached without completion"
                state["errors"].append(error_msg)
                logger.warning(error_msg)
                final_state = state  # Use the last known state
                
            # Return results
            return {
                "target": target,
                "scope": scope,
                "results": final_state["results"],
                "errors": final_state["errors"],
                "completed_tasks": final_state["completed_tasks"],
                "logs": final_state["logs"]
            }
            
        except Exception as e:
            logger.error(f"Error in security audit: {str(e)}")
            raise

# Create singleton instance
security_agent = SecurityAgent()
