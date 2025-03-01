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

from ..config.settings import settings
from ..utils.logger import logger
from ..utils.scope_validator import scope_validator
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
                error_msg = f"Maximum iterations ({self.max_iterations}) reached"
                state["errors"].append(error_msg)
                state["should_continue"] = False
                return False
                
            # Stop if we've encountered a critical error
            if any("quota exceeded" in str(error).lower() for error in state["errors"]):
                state["should_continue"] = False
                return False
                
            # Stop if we have no more tasks and none are currently executing
            if not state["task_list"] and not state["current_task"]:
                state["should_continue"] = False
                return False
                
            # Stop if we have any parsing errors
            if any("error parsing response" in str(error).lower() for error in state["errors"]):
                state["should_continue"] = False
                return False
                
            return state["should_continue"]
            
        workflow.add_conditional_edges(
            "plan",
            should_continue,
            {
                True: "execute",
                False: END
            }
        )
        
        workflow.add_conditional_edges(
            "execute",
            should_continue,
            {
                True: "process",
                False: END
            }
        )
        
        workflow.add_conditional_edges(
            "process",
            should_continue,
            {
                True: "plan",
                False: END
            }
        )

        # Configure checkpointing
        checkpointer = MemorySaver()
        
        # Compile the graph
        return workflow.compile(checkpointer=checkpointer)
        
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
        """Execute the next task in the queue."""
        try:
            # Skip if no tasks or current task is running
            if not state["task_list"]:
                return state
                
            # Get next task
            next_task = state["task_list"][0]
            task_id = str(id(next_task))
            
            # Validate target is in scope
            if not await scope_validator.validate_target(next_task["target"]):
                error_msg = f"Target {next_task['target']} is not in scope"
                logger.error(error_msg)
                state["errors"].append(error_msg)
                state["task_list"].pop(0)  # Remove the out-of-scope task
                return state
                
            # Set as current task
            state["current_task"] = next_task
            
            # Log task start
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "action": "task_start",
                "task_id": task_id,
                "tool": next_task["tool"],
                "target": next_task["target"]
            }
            state["logs"].append(log_entry)
            
            # Execute the task
            try:
                logger.info(f"Executing {next_task['tool']} on {next_task['target']}")
                tool = self.tools.get(next_task["tool"])
                if not tool:
                    raise ValueError(f"Unknown tool: {next_task['tool']}")
                    
                result = await tool(
                    next_task["target"],
                    **(next_task.get("parameters", {}) or {})
                )
                
                # Store results
                state["results"][task_id] = {
                    "tool": next_task["tool"],
                    "target": next_task["target"],
                    "parameters": next_task.get("parameters", {}),
                    "status": "completed",
                    "output": result,
                    "timestamp": datetime.now().isoformat()
                }
                
                # Add to completed tasks
                state["completed_tasks"].append(next_task)
                
                # Log success
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "action": "task_complete",
                    "task_id": task_id,
                    "status": "success"
                }
                state["logs"].append(log_entry)
                
                # Remove from task list
                state["task_list"].pop(0)
                
            except Exception as e:
                logger.error(f"Error executing task: {str(e)}")
                retry_count = state["retry_count"].get(task_id, 0)
                
                if retry_count < self.max_retries:
                    # Increment retry count
                    state["retry_count"][task_id] = retry_count + 1
                    
                    # Log retry
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "action": "task_retry",
                        "task_id": task_id,
                        "attempt": retry_count + 1,
                        "error": str(e)
                    }
                    state["logs"].append(log_entry)
                    
                    logger.info(f"Retrying task (attempt {retry_count + 1})")
                else:
                    # Log failure
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "action": "task_failed",
                        "task_id": task_id,
                        "error": str(e)
                    }
                    state["logs"].append(log_entry)
                    
                    logger.error(f"Max retries ({self.max_retries}) reached for task")
                    state["errors"].append(str(e))
                    state["results"][task_id] = {
                        "tool": next_task["tool"],
                        "target": next_task["target"],
                        "parameters": next_task.get("parameters", {}),
                        "status": "failed",
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    }
                    state["task_list"].pop(0)
                    
            finally:
                # Clear current task
                state["current_task"] = None
                
            return state
            
        except Exception as e:
            logger.error(f"Critical error in task execution: {str(e)}")
            state["errors"].append(str(e))
            state["should_continue"] = False
            return state
            
    async def _process_results(self, state: AgentState) -> AgentState:
        """Process task results and update task list."""
        try:
            # Get the latest completed task result
            completed_tasks = state["completed_tasks"]
            if not completed_tasks:
                return state
                
            latest_task = completed_tasks[-1]
            task_id = str(id(latest_task))
            current_result = state["results"].get(task_id)
            
            if not current_result:
                return state
                
            try:
                # Get task execution decision from Gemini
                response = await self.gemini.generate_content(
                    self.task_execution_prompt.format(
                        target=state["target"],
                        scope=json.dumps(state["scope"]),
                        results=json.dumps(current_result)
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
                        decision = json.loads(response_text)
                    except json.JSONDecodeError:
                        # Try parsing with ast.literal_eval for safer string evaluation
                        import ast
                        decision = ast.literal_eval(response_text)
                    
                    # Validate decision structure
                    if not isinstance(decision, dict):
                        raise ValueError("Expected a dictionary with decision data")
                    if "new_tasks" not in decision:
                        raise ValueError("Missing 'new_tasks' in decision")
                    if not isinstance(decision["new_tasks"], list):
                        raise ValueError("'new_tasks' must be a list")
                        
                    # Validate each new task
                    for task in decision["new_tasks"]:
                        if not isinstance(task, dict):
                            raise ValueError("Each task must be a dictionary")
                        required_fields = {"tool", "target", "priority"}
                        if not all(field in task for field in required_fields):
                            raise ValueError(f"Task missing required fields: {required_fields}")
                        
                except (json.JSONDecodeError, ValueError, SyntaxError) as e:
                    logger.error(f"Error parsing task execution response: {str(e)}")
                    # If we can't parse the response, just continue without adding new tasks
                    state["should_continue"] = len(state["task_list"]) > 0
                    return state
                
                # Handle retry decision
                if decision.get("retry_current", False):
                    retry_count = state["retry_count"].get(task_id, 0)
                    if retry_count < self.max_retries:
                        # Update task parameters
                        latest_task["parameters"].update(
                            decision.get("retry_parameters", {})
                        )
                        # Add task back to the list for retry
                        state["task_list"].insert(0, latest_task)
                        return state
                        
                # Add new tasks
                new_tasks = decision.get("new_tasks", [])
                if new_tasks:
                    # Log new tasks
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "action": "tasks_added",
                        "count": len(new_tasks),
                        "source_task": task_id
                    }
                    state["logs"].append(log_entry)
                    
                    # Add to task list
                    state["task_list"].extend(new_tasks)
                    
                    # Sort tasks by priority and dependencies
                    state["task_list"].sort(
                        key=lambda x: (x["priority"], len(x.get("depends_on", [])))
                    )
                    
                    logger.info(f"Added {len(new_tasks)} new tasks based on results")
                else:
                    # No new tasks and no current tasks means we're done
                    state["should_continue"] = len(state["task_list"]) > 0
                    
                return state
                
            except RuntimeError as e:
                if "quota exceeded" in str(e).lower():
                    logger.error(f"Rate limit error: {str(e)}")
                    state["errors"].append(str(e))
                    state["should_continue"] = False
                    return state
                raise
                
        except Exception as e:
            logger.error(f"Error processing results: {str(e)}")
            # Don't stop the workflow for errors in task execution
            state["should_continue"] = len(state["task_list"]) > 0
            return state
            
    async def run_security_audit(self, target: str, scope: Dict[str, Any]) -> Dict[str, Any]:
        """Run a security audit workflow on the target."""
        try:
            # Configure scope
            scope_validator.update_scope(scope)
            
            # Initialize state
            state = AgentState(
                messages=[],
                task_list=[],
                current_task=None,
                results={},
                errors=[],
                retry_count={},
                completed_tasks=[],
                iteration_count=0,
                should_continue=True,
                logs=[],
                target=target,
                scope=scope
            )
            
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
