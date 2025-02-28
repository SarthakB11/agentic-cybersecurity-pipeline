#!/bin/bash

# Create main project directories
mkdir -p src/{agents,tools,utils,config}
mkdir -p tests
mkdir -p logs
mkdir -p data

# Create main Python files
touch src/__init__.py
touch src/agents/__init__.py
touch src/agents/security_agent.py
touch src/agents/task_manager.py
touch src/tools/__init__.py
touch src/tools/nmap_tool.py
touch src/tools/gobuster_tool.py
touch src/tools/ffuf_tool.py
touch src/tools/sqlmap_tool.py
touch src/utils/__init__.py
touch src/utils/scope_validator.py
touch src/utils/logger.py
touch src/config/__init__.py
touch src/config/settings.py

# Create test files
touch tests/__init__.py
touch tests/test_security_agent.py
touch tests/test_scope_validator.py
touch tests/test_tools.py

# Create main application files
touch app.py
touch streamlit_app.py
touch README.md

# Create environment and configuration files
touch .env.example
touch .gitignore 