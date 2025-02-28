import streamlit as st
import asyncio
from typing import Dict, List, Any
import json
from datetime import datetime
from pathlib import Path

from src.agents.security_agent import security_agent
from src.utils.scope_validator import scope_validator
from src.config.settings import settings
from src.utils.logger import logger

# Page configuration
st.set_page_config(
    page_title="Security Testing Pipeline",
    page_icon="🔒",
    layout="wide"
)

# Initialize session state
if "audit_running" not in st.session_state:
    st.session_state.audit_running = False
if "audit_results" not in st.session_state:
    st.session_state.audit_results = None
if "current_tasks" not in st.session_state:
    st.session_state.current_tasks = []
if "completed_tasks" not in st.session_state:
    st.session_state.completed_tasks = []
if "task_status" not in st.session_state:
    st.session_state.task_status = {}

# Title and description
st.title("🔒 Agentic Security Testing Pipeline")
st.markdown("""
This application provides an autonomous security testing pipeline that can:
- Break down security tasks into executable steps
- Execute various security tools (nmap, gobuster, ffuf, sqlmap)
- Enforce scope constraints
- Dynamically update tasks based on findings
""")

# Sidebar for configuration
with st.sidebar:
    st.header("Configuration")
    
    # Target input
    target = st.text_input(
        "Target URL/IP",
        placeholder="e.g., example.com or 192.168.1.1"
    )
    
    # Scope configuration
    st.subheader("Scope Configuration")
    allowed_domains = st.text_area(
        "Allowed Domains (one per line)",
        placeholder="example.com\n*.example.com"
    ).split("\n")
    
    allowed_ips = st.text_area(
        "Allowed IP Ranges (one per line)",
        placeholder="192.168.1.0/24\n10.0.0.0/8"
    ).split("\n")
    
    excluded_paths = st.text_area(
        "Excluded Paths (one per line)",
        placeholder="/admin\n/backup"
    ).split("\n")
    
    # Tool configuration
    st.subheader("Tool Configuration")
    max_retries = st.number_input("Max Retries", min_value=1, value=3)
    concurrent_tasks = st.number_input("Concurrent Tasks", min_value=1, value=5)
    
    # Start button
    start_audit = st.button(
        "Start Security Audit",
        disabled=st.session_state.audit_running
    )

# Main content area
col1, col2 = st.columns([2, 1])

with col1:
    # Task status and progress
    st.header("Task Status")
    
    if st.session_state.current_tasks:
        st.subheader("Current Tasks")
        for task in st.session_state.current_tasks:
            with st.expander(f"{task['tool']} - {task['target']}", expanded=True):
                st.json(task)
                
    if st.session_state.completed_tasks:
        st.subheader("Completed Tasks")
        for task in st.session_state.completed_tasks:
            status_color = "🟢" if task["status"] == "completed" else "🔴"
            with st.expander(f"{status_color} {task['tool']} - {task['target']}"):
                st.json(task)

with col2:
    # Results and findings
    st.header("Results & Findings")
    
    if st.session_state.audit_results:
        # Display summary statistics
        st.subheader("Summary")
        summary = st.session_state.audit_results.get("summary", {})
        st.metric("Total Tasks", summary.get("total_tasks", 0))
        st.metric("Completed", summary.get("completed", 0))
        st.metric("Success Rate", f"{summary.get('success_rate', 0):.1f}%")
        
        # Display findings
        st.subheader("Findings")
        findings = st.session_state.audit_results.get("findings", [])
        for finding in findings:
            with st.expander(f"{finding['severity']} - {finding['title']}"):
                st.markdown(f"**Description:** {finding['description']}")
                st.markdown(f"**Impact:** {finding['impact']}")
                if finding.get("recommendation"):
                    st.markdown(f"**Recommendation:** {finding['recommendation']}")
                if finding.get("evidence"):
                    st.code(finding["evidence"])

async def run_security_audit():
    """Run the security audit asynchronously."""
    try:
        # Update session state
        st.session_state.audit_running = True
        st.session_state.current_tasks = []
        st.session_state.completed_tasks = []
        st.session_state.audit_results = None
        
        # Prepare scope configuration
        scope = {
            "allowed_domains": [d.strip() for d in allowed_domains if d.strip()],
            "allowed_ips": [ip.strip() for ip in allowed_ips if ip.strip()],
            "excluded_paths": [p.strip() for p in excluded_paths if p.strip()]
        }
        
        # Update settings
        settings.MAX_RETRIES = max_retries
        
        # Run the security audit
        results = await security_agent.run_security_audit(target, scope)
        
        # Process and store results
        st.session_state.audit_results = {
            "summary": {
                "total_tasks": len(results["results"]),
                "completed": sum(1 for r in results["results"].values() if r["status"] == "completed"),
                "failed": sum(1 for r in results["results"].values() if r["status"] == "failed"),
                "success_rate": sum(1 for r in results["results"].values() if r["status"] == "completed") / len(results["results"]) * 100 if results["results"] else 0
            },
            "findings": process_findings(results)
        }
        
    except Exception as e:
        st.error(f"Error during security audit: {str(e)}")
        logger.error(f"Security audit error: {str(e)}")
        
    finally:
        st.session_state.audit_running = False

def process_findings(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Process raw results into structured findings."""
    findings = []
    
    # Process nmap results
    for task_id, task in results["results"].items():
        if task["tool"] == "nmap_scan" and task["status"] == "completed":
            findings.extend(process_nmap_findings(task["result"]))
            
        elif task["tool"] == "directory_scan" and task["status"] == "completed":
            findings.extend(process_gobuster_findings(task["result"]))
            
        elif task["tool"] == "fuzzing_scan" and task["status"] == "completed":
            findings.extend(process_ffuf_findings(task["result"]))
            
        elif task["tool"] == "sql_injection_scan" and task["status"] == "completed":
            findings.extend(process_sqlmap_findings(task["result"]))
            
    return findings

def process_nmap_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Process nmap results into findings."""
    findings = []
    
    for host in result.get("hosts", []):
        for port in host.get("ports", []):
            service = port["service"]
            finding = {
                "severity": "Medium" if port["portid"] in ["80", "443", "22", "3389"] else "Low",
                "title": f"Open Port {port['portid']}/{port['protocol']}",
                "description": f"Found open port {port['portid']} running {service['name']}",
                "impact": "This port could potentially be exploited if not properly secured.",
                "evidence": f"Service: {service['name']}\nProduct: {service['product']}\nVersion: {service['version']}"
            }
            findings.append(finding)
            
    return findings

def process_gobuster_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Process gobuster results into findings."""
    findings = []
    
    for directory in result.get("directories", []):
        finding = {
            "severity": "Medium" if any(p in directory["url"] for p in ["admin", "backup", "config"]) else "Low",
            "title": f"Directory Discovered: {directory['url']}",
            "description": f"Found accessible directory at {directory['url']}",
            "impact": "This directory might contain sensitive information or functionality.",
            "evidence": f"Status Code: {directory['status_code']}\nSize: {directory['size']}"
        }
        findings.append(finding)
        
    return findings

def process_ffuf_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Process ffuf results into findings."""
    findings = []
    
    for entry in result.get("results", []):
        if entry["status"] in [200, 301, 302, 403]:
            finding = {
                "severity": "High" if entry["status"] == 200 else "Medium",
                "title": f"Endpoint Found: {entry['url']}",
                "description": f"Discovered endpoint with status {entry['status']}",
                "impact": "This endpoint might expose sensitive functionality or information.",
                "evidence": f"Status: {entry['status']}\nContent Length: {entry['length']}\nWords: {entry['words']}"
            }
            findings.append(finding)
            
    return findings

def process_sqlmap_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Process sqlmap results into findings."""
    findings = []
    
    if result.get("vulnerable", False):
        finding = {
            "severity": "Critical",
            "title": "SQL Injection Vulnerability",
            "description": f"Found SQL injection vulnerability in target",
            "impact": "This vulnerability could allow an attacker to access or modify the database.",
            "evidence": f"Database Type: {result.get('database_type')}\nVulnerabilities: {', '.join(result.get('vulnerabilities', []))}"
        }
        findings.append(finding)
        
    return findings

# Handle start button click
if start_audit:
    if not target:
        st.error("Please enter a target URL or IP address")
    elif not any(allowed_domains) and not any(allowed_ips):
        st.error("Please configure at least one allowed domain or IP range")
    else:
        asyncio.run(run_security_audit())
