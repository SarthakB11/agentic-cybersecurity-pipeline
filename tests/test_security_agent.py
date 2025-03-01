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

# Mock tool responses
MOCK_NMAP_OUTPUT = {
    "hosts": [
        {
            "address": "93.184.216.34",
            "hostnames": ["example.com"],
            "ports": [
                {
                    "protocol": "tcp",
                    "portid": "80",
                    "state": "open",
                    "service": {
                        "name": "http",
                        "product": "nginx",
                        "version": "1.18.0",
                        "extrainfo": ""
                    }
                },
                {
                    "protocol": "tcp",
                    "portid": "443",
                    "state": "open",
                    "service": {
                        "name": "https",
                        "product": "nginx",
                        "version": "1.18.0",
                        "extrainfo": ""
                    }
                }
            ]
        }
    ]
}

MOCK_GOBUSTER_OUTPUT = {
    "directories": [
        {
            "url": "/api",
            "status_code": "200",
            "size": "1234"
        },
        {
            "url": "/docs",
            "status_code": "200",
            "size": "4567"
        }
    ],
    "files": [
        {
            "url": "/robots.txt",
            "status_code": "200",
            "size": "123"
        }
    ],
    "total_found": 3
}

MOCK_FFUF_OUTPUT = {
    "results": [
        {
            "url": "/api/v1",
            "status": 200,
            "length": 1234,
            "words": 123,
            "lines": 45,
            "content_type": "application/json",
            "redirect_location": ""
        },
        {
            "url": "/api/v2",
            "status": 403,
            "length": 567,
            "words": 89,
            "lines": 12,
            "content_type": "text/html",
            "redirect_location": ""
        }
    ],
    "statistics": {
        "total_requests": 1000,
        "total_time": 60,
        "req_per_sec": 16.67
    }
}

MOCK_SQLMAP_OUTPUT = {
    "vulnerable": True,
    "database_type": "MySQL",
    "vulnerabilities": [
        "boolean-based blind",
        "time-based blind"
    ],
    "databases": ["testdb", "information_schema"],
    "tables": [
        {"database": "testdb", "table": "users"},
        {"database": "testdb", "table": "products"}
    ],
    "columns": [
        {
            "database": "testdb",
            "table": "users",
            "columns": ["id", "username", "password"]
        }
    ],
    "data": ["sample data found"],
    "error": None
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
        "nmap_scan": AsyncMock(return_value=MOCK_NMAP_OUTPUT),
        "directory_scan": AsyncMock(return_value=MOCK_GOBUSTER_OUTPUT),
        "fuzzing_scan": AsyncMock(return_value=MOCK_FFUF_OUTPUT),
        "sql_injection_scan": AsyncMock(return_value=MOCK_SQLMAP_OUTPUT)
    }
    return agent

@pytest.mark.asyncio
async def test_nmap_scan_output_processing(security_agent, mock_gemini):
    """Test processing of nmap scan outputs."""
    # Set up mock response for task planning
    mock_gemini.generate_content.side_effect = [
        '''[{"tool": "nmap_scan", "target": "example.com", "parameters": {"ports": "80,443"}, "priority": 1, "depends_on": []}]''',
        MOCK_TASK_EXECUTION_RESPONSE,
        "[]"
    ]
    
    results = await security_agent.run_security_audit(TEST_TARGET, TEST_SCOPE)
    
    # Verify nmap results processing
    nmap_results = next(
        (r for r in results["results"].values() if r["tool"] == "nmap_scan"),
        None
    )
    assert nmap_results is not None
    assert nmap_results["status"] == "completed"
    assert len(nmap_results["result"]["hosts"]) == 1
    assert len(nmap_results["result"]["hosts"][0]["ports"]) == 2
    assert nmap_results["result"]["hosts"][0]["ports"][0]["service"]["name"] in ["http", "https"]

@pytest.mark.asyncio
async def test_gobuster_output_processing(security_agent, mock_gemini):
    """Test processing of gobuster directory scan outputs."""
    mock_gemini.generate_content.side_effect = [
        '''[{"tool": "directory_scan", "target": "example.com", "parameters": {"wordlist": "common.txt"}, "priority": 1, "depends_on": []}]''',
        MOCK_TASK_EXECUTION_RESPONSE,
        "[]"
    ]
    
    results = await security_agent.run_security_audit(TEST_TARGET, TEST_SCOPE)
    
    # Verify gobuster results processing
    gobuster_results = next(
        (r for r in results["results"].values() if r["tool"] == "directory_scan"),
        None
    )
    assert gobuster_results is not None
    assert gobuster_results["status"] == "completed"
    assert len(gobuster_results["result"]["directories"]) == 2
    assert len(gobuster_results["result"]["files"]) == 1
    assert gobuster_results["result"]["total_found"] == 3
    assert "/api" in [d["url"] for d in gobuster_results["result"]["directories"]]

@pytest.mark.asyncio
async def test_ffuf_output_processing(security_agent, mock_gemini):
    """Test processing of ffuf fuzzing scan outputs."""
    mock_gemini.generate_content.side_effect = [
        '''[{"tool": "fuzzing_scan", "target": "example.com", "parameters": {"wordlist": "api.txt"}, "priority": 1, "depends_on": []}]''',
        MOCK_TASK_EXECUTION_RESPONSE,
        "[]"
    ]
    
    results = await security_agent.run_security_audit(TEST_TARGET, TEST_SCOPE)
    
    # Verify ffuf results processing
    ffuf_results = next(
        (r for r in results["results"].values() if r["tool"] == "fuzzing_scan"),
        None
    )
    assert ffuf_results is not None
    assert ffuf_results["status"] == "completed"
    assert len(ffuf_results["result"]["results"]) == 2
    assert ffuf_results["result"]["statistics"]["total_requests"] == 1000
    assert any(r["status"] == 200 for r in ffuf_results["result"]["results"])
    assert any(r["url"].startswith("/api/") for r in ffuf_results["result"]["results"])

@pytest.mark.asyncio
async def test_sqlmap_output_processing(security_agent, mock_gemini):
    """Test processing of sqlmap scan outputs."""
    mock_gemini.generate_content.side_effect = [
        '''[{"tool": "sql_injection_scan", "target": "example.com", "parameters": {}, "priority": 1, "depends_on": []}]''',
        MOCK_TASK_EXECUTION_RESPONSE,
        "[]"
    ]
    
    results = await security_agent.run_security_audit(TEST_TARGET, TEST_SCOPE)
    
    # Verify sqlmap results processing
    sqlmap_results = next(
        (r for r in results["results"].values() if r["tool"] == "sql_injection_scan"),
        None
    )
    assert sqlmap_results is not None
    assert sqlmap_results["status"] == "completed"
    assert sqlmap_results["result"]["vulnerable"] is True
    assert sqlmap_results["result"]["database_type"] == "MySQL"
    assert len(sqlmap_results["result"]["vulnerabilities"]) == 2
    assert len(sqlmap_results["result"]["databases"]) == 2
    assert len(sqlmap_results["result"]["tables"]) == 2
    assert "users" in [t["table"] for t in sqlmap_results["result"]["tables"]]

@pytest.mark.asyncio
async def test_tool_error_handling(security_agent, mock_gemini):
    """Test handling of tool execution errors."""
    # Make tools fail with different errors
    security_agent.tools["nmap_scan"] = AsyncMock(side_effect=RuntimeError("Connection timeout"))
    security_agent.tools["directory_scan"] = AsyncMock(side_effect=ValueError("Invalid response"))
    security_agent.tools["fuzzing_scan"] = AsyncMock(side_effect=Exception("Unknown error"))
    
    mock_gemini.generate_content.side_effect = [
        '''[
            {"tool": "nmap_scan", "target": "example.com", "parameters": {}, "priority": 1, "depends_on": []},
            {"tool": "directory_scan", "target": "example.com", "parameters": {}, "priority": 2, "depends_on": []},
            {"tool": "fuzzing_scan", "target": "example.com", "parameters": {}, "priority": 3, "depends_on": []}
        ]''',
        MOCK_TASK_EXECUTION_RESPONSE,
        "[]"
    ]
    
    results = await security_agent.run_security_audit(TEST_TARGET, TEST_SCOPE)
    
    # Verify error handling
    assert len(results["errors"]) > 0
    assert any("Connection timeout" in str(error) for error in results["errors"])
    assert any("Invalid response" in str(error) for error in results["errors"])
    assert any("Unknown error" in str(error) for error in results["errors"])

@pytest.mark.asyncio
async def test_mixed_tool_results(security_agent, mock_gemini):
    """Test processing of mixed successful and failed tool results."""
    # Make some tools succeed and others fail
    security_agent.tools["nmap_scan"] = AsyncMock(return_value=MOCK_NMAP_OUTPUT)
    security_agent.tools["directory_scan"] = AsyncMock(side_effect=RuntimeError("Failed"))
    security_agent.tools["fuzzing_scan"] = AsyncMock(return_value=MOCK_FFUF_OUTPUT)
    
    mock_gemini.generate_content.side_effect = [
        '''[
            {"tool": "nmap_scan", "target": "example.com", "parameters": {}, "priority": 1, "depends_on": []},
            {"tool": "directory_scan", "target": "example.com", "parameters": {}, "priority": 2, "depends_on": []},
            {"tool": "fuzzing_scan", "target": "example.com", "parameters": {}, "priority": 3, "depends_on": []}
        ]''',
        MOCK_TASK_EXECUTION_RESPONSE,
        "[]"
    ]
    
    results = await security_agent.run_security_audit(TEST_TARGET, TEST_SCOPE)
    
    # Verify mixed results processing
    successful_tasks = [r for r in results["results"].values() if r["status"] == "completed"]
    failed_tasks = [r for r in results["results"].values() if r["status"] == "failed"]
    
    assert len(successful_tasks) == 2  # nmap and ffuf should succeed
    assert len(failed_tasks) == 1  # directory scan should fail
    assert any(r["tool"] == "directory_scan" and "Failed" in str(r.get("error", "")) for r in results["results"].values())

@pytest.mark.asyncio
async def test_task_dependencies_handling(security_agent, mock_gemini):
    """Test handling of task dependencies and execution order."""
    mock_gemini.generate_content.side_effect = [
        '''[
            {"tool": "nmap_scan", "target": "example.com", "parameters": {}, "priority": 1, "depends_on": []},
            {"tool": "directory_scan", "target": "example.com", "parameters": {}, "priority": 2, "depends_on": ["1"]},
            {"tool": "fuzzing_scan", "target": "example.com", "parameters": {}, "priority": 3, "depends_on": ["2"]}
        ]''',
        MOCK_TASK_EXECUTION_RESPONSE,
        "[]"
    ]
    
    results = await security_agent.run_security_audit(TEST_TARGET, TEST_SCOPE)
    
    # Verify execution order based on dependencies
    task_order = [(r["tool"], r["started_at"]) for r in results["results"].values()]
    task_order.sort(key=lambda x: x[1])  # Sort by start time
    
    tools_in_order = [t[0] for t in task_order]
    assert tools_in_order.index("nmap_scan") < tools_in_order.index("directory_scan")
    assert tools_in_order.index("directory_scan") < tools_in_order.index("fuzzing_scan")

if __name__ == "__main__":
    pytest.main(["-v", "test_security_agent.py"])
