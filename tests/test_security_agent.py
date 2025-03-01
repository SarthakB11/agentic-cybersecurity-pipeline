import pytest
import asyncio
import json
from typing import Dict, Any
from unittest.mock import AsyncMock, patch, MagicMock

from src.agents.security_agent import SecurityAgent, AgentState, GeminiAPI
from src.utils.scope_validator import scope_validator

# Test data
TEST_TARGET = "example.com"
TEST_SCOPE = {
    "allowed_domains": ["example.com", "*.example.com"],
    "allowed_ips": ["93.184.216.0/24"],
    "excluded_paths": ["/admin", "/backup"]
}

# Mock Gemini API responses
MOCK_TASK_PLANNING_RESPONSE = '''[
    {
        "tool": "nmap_scan",
        "target": "example.com",
        "parameters": {"ports": "80,443"},
        "priority": 1,
        "depends_on": []
    },
    {
        "tool": "directory_scan",
        "target": "example.com",
        "parameters": {"wordlist": "common.txt"},
        "priority": 2,
        "depends_on": ["1"]
    }
]'''

MOCK_TASK_EXECUTION_RESPONSE = '''{
    "new_tasks": [
        {
            "tool": "fuzzing_scan",
            "target": "http://example.com/api",
            "parameters": {"wordlist": "api.txt"},
            "priority": 2,
            "depends_on": []
        }
    ],
    "retry_current": false,
    "retry_parameters": {}
}'''

@pytest.fixture
def mock_gemini():
    """Create a mock Gemini API."""
    with patch('src.agents.security_agent.GeminiAPI') as mock:
        mock_instance = MagicMock()
        mock_instance.generate_content = AsyncMock()
        mock.return_value = mock_instance
        yield mock_instance

@pytest.fixture
def security_agent(mock_gemini):
    """Create a security agent with mocked dependencies."""
    agent = SecurityAgent()
    # Mock tool responses
    agent.tools = {
        "nmap_scan": AsyncMock(return_value={"hosts": [{"address": "93.184.216.34", "ports": [{"portid": "80", "state": "open"}]}]}),
        "directory_scan": AsyncMock(return_value={"directories": [{"url": "/api", "status_code": "200"}]}),
        "fuzzing_scan": AsyncMock(return_value={"results": [{"url": "/api/v1", "status": 200}]}),
        "sql_injection_scan": AsyncMock(return_value={"vulnerable": False})
    }
    return agent

@pytest.mark.asyncio
async def test_basic_security_audit(security_agent, mock_gemini):
    """Test a basic security audit workflow."""
    # Set up mock responses
    mock_gemini.generate_content.side_effect = [
        MOCK_TASK_PLANNING_RESPONSE,
        MOCK_TASK_EXECUTION_RESPONSE,
        "[]"  # No more tasks
    ]
    
    # Run security audit
    results = await security_agent.run_security_audit(TEST_TARGET, TEST_SCOPE)
    
    # Verify results
    assert results["target"] == TEST_TARGET
    assert results["scope"] == TEST_SCOPE
    assert len(results["results"]) > 0
    assert not results["errors"]
    
    # Verify tool calls
    assert security_agent.tools["nmap_scan"].called
    assert security_agent.tools["directory_scan"].called

@pytest.mark.asyncio
async def test_out_of_scope_target(security_agent, mock_gemini):
    """Test handling of out-of-scope targets."""
    # Set up mock responses
    mock_gemini.generate_content.side_effect = [
        '''[{"tool": "nmap_scan", "target": "evil.com", "parameters": {}, "priority": 1, "depends_on": []}]'''
    ]
    
    results = await security_agent.run_security_audit(
        "evil.com",
        TEST_SCOPE
    )
    
    assert "errors" in results
    assert any("not in scope" in str(error).lower() for error in results["errors"])

@pytest.mark.asyncio
async def test_tool_failure_retry(security_agent, mock_gemini):
    """Test tool failure and retry mechanism."""
    # Make nmap tool fail first, then succeed
    fail_then_succeed = AsyncMock()
    fail_then_succeed.side_effect = [
        RuntimeError("Tool failed"),
        {"hosts": [{"address": "93.184.216.34", "ports": [{"portid": "80", "state": "open"}]}]}
    ]
    security_agent.tools["nmap_scan"] = fail_then_succeed
    
    # Set up mock responses
    mock_gemini.generate_content.side_effect = [
        '''[{"tool": "nmap_scan", "target": "example.com", "parameters": {}, "priority": 1, "depends_on": []}]''',
        MOCK_TASK_EXECUTION_RESPONSE,
        "[]"  # No more tasks
    ]
    
    # Run security audit
    results = await security_agent.run_security_audit(TEST_TARGET, TEST_SCOPE)
    
    # Verify retry behavior
    assert fail_then_succeed.call_count == 2
    assert len(results["results"]) > 0

@pytest.mark.asyncio
async def test_dynamic_task_addition(security_agent, mock_gemini):
    """Test dynamic addition of tasks based on findings."""
    # Set up mock responses for task planning and execution
    mock_gemini.generate_content.side_effect = [
        # Initial task planning
        '''[{"tool": "nmap_scan", "target": "example.com", "parameters": {}, "priority": 1, "depends_on": []}]''',
        # Process results - add new task based on findings
        '''{
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
        }''',
        # Process second task results
        '''{
            "new_tasks": [],
            "retry_current": false,
            "retry_parameters": {}
        }'''
    ]
    
    # Run security audit
    results = await security_agent.run_security_audit(TEST_TARGET, TEST_SCOPE)
    
    # Verify that both tools were called
    assert security_agent.tools["nmap_scan"].called
    assert security_agent.tools["directory_scan"].called
    assert len(results["results"]) >= 2

@pytest.mark.asyncio
async def test_scope_validation():
    """Test scope validation functionality."""
    # Configure scope validator
    scope_validator.allowed_domains = ["example.com", "*.example.com"]
    scope_validator.allowed_ips = ["93.184.216.0/24"]
    scope_validator.excluded_paths = ["/admin", "/backup"]
    
    # Test valid cases
    assert await scope_validator.validate_target("example.com")
    assert await scope_validator.validate_target("sub.example.com")
    assert await scope_validator.validate_target("93.184.216.34")
    
    # Test invalid cases
    assert not await scope_validator.validate_target("evil.com")
    assert not await scope_validator.validate_target("10.0.0.1")
    
    # Test excluded paths
    assert not await scope_validator.validate_target("example.com/admin")
    assert not await scope_validator.validate_target("example.com/backup/db")

@pytest.mark.asyncio
async def test_rate_limiting(security_agent, mock_gemini):
    """Test handling of API rate limiting."""
    # Make Gemini API fail with rate limit error first, then succeed
    mock_gemini.generate_content.side_effect = [
        RuntimeError("Quota exceeded for quota metric 'Generate Content API requests per minute'"),
        MOCK_TASK_PLANNING_RESPONSE,
        MOCK_TASK_EXECUTION_RESPONSE,
        "[]"  # No more tasks
    ]
    
    # Run security audit
    results = await security_agent.run_security_audit(TEST_TARGET, TEST_SCOPE)
    
    # Verify error handling
    assert "errors" in results
    assert any("quota exceeded" in str(error).lower() for error in results["errors"])

@pytest.mark.asyncio
async def test_iteration_limit(security_agent, mock_gemini):
    """Test that the workflow respects the iteration limit."""
    # Make the workflow keep generating tasks
    mock_gemini.generate_content.side_effect = lambda _: '''[
        {"tool": "nmap_scan", "target": "example.com", "parameters": {}, "priority": 1, "depends_on": []}
    ]'''
    
    # Run security audit
    results = await security_agent.run_security_audit(TEST_TARGET, TEST_SCOPE)
    
    # Verify that the workflow stopped due to iteration limit
    assert len(results["errors"]) > 0
    assert any("maximum iterations" in str(error).lower() for error in results["errors"])

if __name__ == "__main__":
    pytest.main(["-v", "test_security_agent.py"])
