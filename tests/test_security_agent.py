import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from typing import Dict, Any

from src.agents.security_agent import security_agent, AgentState
from src.utils.scope_validator import scope_validator

@pytest.fixture
def mock_tool_executor():
    """Create a mock tool executor."""
    executor = AsyncMock()
    executor.ainvoke = AsyncMock()
    return executor

@pytest.fixture
def mock_llm():
    """Create a mock LLM."""
    llm = AsyncMock()
    llm.ainvoke = AsyncMock()
    return llm

@pytest.fixture
def basic_state() -> AgentState:
    """Create a basic agent state for testing."""
    return AgentState(
        messages=[],
        task_list=[],
        current_task=None,
        results={},
        errors=[]
    )

@pytest.mark.asyncio
async def test_plan_tasks(mock_llm, basic_state):
    """Test task planning functionality."""
    # Mock LLM response
    mock_response = MagicMock()
    mock_response.content = '''[
        {
            "tool": "nmap_scan",
            "target": "example.com",
            "parameters": {"ports": "80,443"},
            "priority": 1,
            "depends_on": []
        }
    ]'''
    mock_llm.ainvoke.return_value = mock_response
    
    # Replace security agent's LLM with mock
    security_agent.llm = mock_llm
    
    # Run task planning
    new_state = await security_agent._plan_tasks(basic_state)
    
    # Verify results
    assert len(new_state["task_list"]) == 1
    task = new_state["task_list"][0]
    assert task["tool"] == "nmap_scan"
    assert task["target"] == "example.com"
    assert task["priority"] == 1

@pytest.mark.asyncio
async def test_execute_task(mock_tool_executor, basic_state):
    """Test task execution functionality."""
    # Add a task to execute
    task = {
        "tool": "nmap_scan",
        "target": "example.com",
        "parameters": {"ports": "80,443"},
        "priority": 1,
        "depends_on": []
    }
    basic_state["task_list"].append(task)
    
    # Mock tool execution result
    mock_result = {
        "hosts": [
            {
                "address": "93.184.216.34",
                "ports": [
                    {
                        "portid": "80",
                        "state": "open",
                        "service": {
                            "name": "http",
                            "product": "nginx"
                        }
                    }
                ]
            }
        ]
    }
    mock_tool_executor.ainvoke.return_value = mock_result
    
    # Replace tool executor
    security_agent.tool_executor = mock_tool_executor
    
    # Execute task
    new_state = await security_agent._execute_task(basic_state)
    
    # Verify results
    assert len(new_state["task_list"]) == 0
    assert new_state["current_task"] is not None
    assert len(new_state["results"]) == 1
    assert new_state["results"][id(new_state["current_task"])] == mock_result

@pytest.mark.asyncio
async def test_process_results(mock_llm, basic_state):
    """Test results processing functionality."""
    # Add current task and results
    task = {
        "tool": "nmap_scan",
        "target": "example.com",
        "parameters": {"ports": "80,443"},
        "priority": 1,
        "depends_on": []
    }
    basic_state["current_task"] = task
    basic_state["results"][id(task)] = {
        "hosts": [
            {
                "address": "93.184.216.34",
                "ports": [
                    {
                        "portid": "80",
                        "state": "open",
                        "service": {
                            "name": "http",
                            "product": "nginx"
                        }
                    }
                ]
            }
        ]
    }
    
    # Mock LLM response
    mock_response = MagicMock()
    mock_response.content = '''{
        "new_tasks": [
            {
                "tool": "directory_scan",
                "target": "http://example.com",
                "parameters": {},
                "priority": 2,
                "depends_on": []
            }
        ],
        "retry_current": false,
        "retry_parameters": {}
    }'''
    mock_llm.ainvoke.return_value = mock_response
    
    # Replace security agent's LLM with mock
    security_agent.llm = mock_llm
    
    # Process results
    new_state = await security_agent._process_results(basic_state)
    
    # Verify results
    assert new_state["current_task"] is None
    assert len(new_state["task_list"]) == 1
    new_task = new_state["task_list"][0]
    assert new_task["tool"] == "directory_scan"
    assert new_task["target"] == "http://example.com"

@pytest.mark.asyncio
async def test_run_security_audit():
    """Test complete security audit workflow."""
    # Mock dependencies
    mock_llm = AsyncMock()
    mock_tool_executor = AsyncMock()
    
    # Mock responses
    mock_llm.ainvoke.side_effect = [
        MagicMock(content='''[
            {
                "tool": "nmap_scan",
                "target": "example.com",
                "parameters": {"ports": "80,443"},
                "priority": 1,
                "depends_on": []
            }
        ]'''),
        MagicMock(content='''{
            "new_tasks": [],
            "retry_current": false,
            "retry_parameters": {}
        }''')
    ]
    
    mock_tool_executor.ainvoke.return_value = {
        "hosts": [
            {
                "address": "93.184.216.34",
                "ports": [
                    {
                        "portid": "80",
                        "state": "open",
                        "service": {
                            "name": "http",
                            "product": "nginx"
                        }
                    }
                ]
            }
        ]
    }
    
    # Replace dependencies
    security_agent.llm = mock_llm
    security_agent.tool_executor = mock_tool_executor
    
    # Run security audit
    target = "example.com"
    scope = {
        "allowed_domains": ["example.com"],
        "allowed_ips": [],
        "excluded_paths": []
    }
    
    results = await security_agent.run_security_audit(target, scope)
    
    # Verify results
    assert results["target"] == target
    assert results["scope"] == scope
    assert len(results["results"]) > 0
    assert not results["errors"]

def test_scope_validator():
    """Test scope validation functionality."""
    # Configure scope
    scope_validator.allowed_domains = ["example.com", "*.example.com"]
    scope_validator.allowed_ips = [ipaddress.ip_network("192.168.1.0/24")]
    scope_validator.excluded_paths = ["/admin", "/backup"]
    
    # Test domain validation
    assert scope_validator.is_domain_in_scope("example.com")
    assert scope_validator.is_domain_in_scope("sub.example.com")
    assert not scope_validator.is_domain_in_scope("evil.com")
    
    # Test IP validation
    assert scope_validator.is_ip_in_scope("192.168.1.100")
    assert not scope_validator.is_ip_in_scope("10.0.0.1")
    
    # Test path exclusion
    assert scope_validator.is_path_excluded("/admin/config")
    assert scope_validator.is_path_excluded("/backup/db")
    assert not scope_validator.is_path_excluded("/api/v1")
