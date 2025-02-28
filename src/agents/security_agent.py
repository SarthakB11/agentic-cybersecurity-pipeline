from typing import Dict, List, Any, Optional, TypedDict, Annotated
import asyncio
from pydantic import BaseModel, Field
from langchain_core.messages import HumanMessage, AIMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.output_parsers import JsonOutputParser
from langgraph.graph import StateGraph, END
from langgraph.prebuilt.tool_executor import ToolExecutor
from langchain_openai import ChatOpenAI

from ..config.settings import settings
from ..utils.logger import logger
from ..tools.nmap_tool import nmap_tool
from ..tools.gobuster_tool import gobuster_tool
from ..tools.ffuf_tool import ffuf_tool
from ..tools.sqlmap_tool import sqlmap_tool

class AgentState(TypedDict):
    """Type definition for agent state."""
    messages: List[Any]  # List of messages in the conversation
    task_list: List[Dict[str, Any]]  # List of tasks to be executed
    current_task: Optional[Dict[str, Any]]  # Currently executing task
    results: Dict[str, Any]  # Results from executed tasks
    errors: List[str]  # List of errors encountered

class SecurityAgent:
    def __init__(self):
        """Initialize the security agent with LangGraph components."""
        self.llm = ChatOpenAI(
            model=settings.MODEL_NAME,
            temperature=settings.TEMPERATURE,
            api_key=settings.OPENAI_API_KEY
        )
        
        # Set up tools
        self.tools = {
            "nmap_scan": nmap_tool.run,
            "directory_scan": gobuster_tool.run,
            "fuzzing_scan": ffuf_tool.run,
            "sql_injection_scan": sqlmap_tool.run
        }
        
        self.tool_executor = ToolExecutor(self.tools)
        
        # Set up the task planning prompt
        self.task_planning_prompt = ChatPromptTemplate.from_messages([
            MessagesPlaceholder(variable_name="messages"),
            ("system", """You are a security testing assistant. Based on the conversation history and current state,
            determine the next security testing tasks to perform. Tasks should be ordered by priority and dependency.
            
            Each task should include:
            - tool: The security tool to use (nmap_scan, directory_scan, fuzzing_scan, sql_injection_scan)
            - target: The target URL or IP to scan
            - parameters: Dictionary of tool-specific parameters
            - priority: Task priority (1-5, where 1 is highest)
            - depends_on: List of task IDs this task depends on (or empty list)
            
            Output should be a JSON list of tasks."""),
            ("human", "What security testing tasks should be performed next?")
        ])
        
        # Set up the task execution prompt
        self.task_execution_prompt = ChatPromptTemplate.from_messages([
            MessagesPlaceholder(variable_name="messages"),
            ("system", """You are a security testing assistant. Review the results of the last executed task
            and determine if any additional tasks should be added based on the findings.
            
            Consider:
            - New targets discovered (subdomains, IP addresses)
            - Open ports that require further investigation
            - Potential vulnerabilities that need verification
            - Failed tasks that should be retried with different parameters
            
            Output should be a JSON object with:
            - new_tasks: List of new tasks to add
            - retry_current: Boolean indicating if current task should be retried
            - retry_parameters: New parameters if task should be retried"""),
            ("human", "Should any new tasks be added based on the last execution results?")
        ])
        
        # Create the workflow graph
        self.workflow = self._create_workflow()
        
    def _create_workflow(self) -> StateGraph:
        """Create the LangGraph workflow for security testing."""
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("plan_tasks", self._plan_tasks)
        workflow.add_node("execute_task", self._execute_task)
        workflow.add_node("process_results", self._process_results)
        
        # Add edges
        workflow.add_edge("plan_tasks", "execute_task")
        workflow.add_edge("execute_task", "process_results")
        
        # Add conditional edges
        workflow.add_conditional_edges(
            "process_results",
            self._should_continue,
            {
                True: "plan_tasks",
                False: END
            }
        )
        
        # Set entry point
        workflow.set_entry_point("plan_tasks")
        
        return workflow
        
    async def _plan_tasks(self, state: AgentState) -> AgentState:
        """Plan the next security testing tasks."""
        try:
            # Get task planning from LLM
            response = await self.llm.ainvoke(
                self.task_planning_prompt.format(messages=state["messages"])
            )
            
            # Parse the response
            parser = JsonOutputParser()
            new_tasks = parser.parse(response.content)
            
            # Update task list
            state["task_list"].extend(new_tasks)
            
            # Sort tasks by priority and dependencies
            state["task_list"].sort(key=lambda x: (x["priority"], len(x["depends_on"])))
            
            logger.info(f"Planned {len(new_tasks)} new tasks")
            return state
            
        except Exception as e:
            logger.error(f"Error in task planning: {str(e)}")
            state["errors"].append(str(e))
            return state
            
    async def _execute_task(self, state: AgentState) -> AgentState:
        """Execute the next task in the queue."""
        try:
            if not state["task_list"]:
                return state
                
            # Get next executable task (all dependencies completed)
            next_task = None
            for task in state["task_list"]:
                if all(dep in state["results"] for dep in task["depends_on"]):
                    next_task = task
                    break
                    
            if not next_task:
                logger.warning("No executable tasks found")
                return state
                
            # Remove task from list and set as current
            state["task_list"].remove(next_task)
            state["current_task"] = next_task
            
            # Execute the task
            tool_name = next_task["tool"]
            if tool_name not in self.tools:
                raise ValueError(f"Unknown tool: {tool_name}")
                
            logger.info(f"Executing {tool_name} on {next_task['target']}")
            result = await self.tool_executor.ainvoke({
                "name": tool_name,
                "arguments": {
                    "target": next_task["target"],
                    **next_task["parameters"]
                }
            })
            
            # Store results
            state["results"][id(next_task)] = result
            
            return state
            
        except Exception as e:
            logger.error(f"Error executing task: {str(e)}")
            state["errors"].append(str(e))
            return state
            
    async def _process_results(self, state: AgentState) -> AgentState:
        """Process task results and determine if new tasks are needed."""
        try:
            if not state["current_task"] or not state["results"]:
                return state
                
            # Get results processing from LLM
            response = await self.llm.ainvoke(
                self.task_execution_prompt.format(messages=[
                    AIMessage(content=str(state["results"][id(state["current_task"])])),
                    HumanMessage(content="What tasks should be added based on these results?")
                ])
            )
            
            # Parse the response
            parser = JsonOutputParser()
            result_analysis = parser.parse(response.content)
            
            # Add new tasks
            if result_analysis.get("new_tasks"):
                state["task_list"].extend(result_analysis["new_tasks"])
                logger.info(f"Added {len(result_analysis['new_tasks'])} new tasks based on results")
                
            # Handle retry if needed
            if result_analysis.get("retry_current"):
                retry_task = state["current_task"].copy()
                retry_task["parameters"].update(result_analysis.get("retry_parameters", {}))
                state["task_list"].append(retry_task)
                logger.info(f"Scheduled retry of {retry_task['tool']} with new parameters")
                
            # Clear current task
            state["current_task"] = None
            
            return state
            
        except Exception as e:
            logger.error(f"Error processing results: {str(e)}")
            state["errors"].append(str(e))
            return state
            
    def _should_continue(self, state: AgentState) -> bool:
        """Determine if the workflow should continue."""
        # Continue if there are tasks in the queue or a current task
        return bool(state["task_list"]) or bool(state["current_task"])
        
    async def run_security_audit(self, target: str, scope: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run a complete security audit on a target.
        
        Args:
            target: The target URL or IP to audit
            scope: Dictionary defining the audit scope
            
        Returns:
            Dictionary containing all results and findings
        """
        try:
            # Initialize state
            state = AgentState(
                messages=[
                    HumanMessage(content=f"Perform a security audit of {target} within scope {scope}")
                ],
                task_list=[],
                current_task=None,
                results={},
                errors=[]
            )
            
            # Run the workflow
            logger.info(f"Starting security audit of {target}")
            final_state = await self.workflow.arun(state)
            
            # Compile results
            return {
                "target": target,
                "scope": scope,
                "results": final_state["results"],
                "errors": final_state["errors"]
            }
            
        except Exception as e:
            logger.error(f"Error in security audit: {str(e)}")
            return {
                "target": target,
                "scope": scope,
                "results": {},
                "errors": [str(e)]
            }

# Create singleton instance
security_agent = SecurityAgent()
