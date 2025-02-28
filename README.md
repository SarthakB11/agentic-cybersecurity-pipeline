# Agentic Cybersecurity Pipeline

An autonomous security testing pipeline built with LangGraph and LangChain that can dynamically execute and manage security scans while respecting defined scope constraints.

## Features

- **Autonomous Task Management**: Breaks down high-level security tasks into executable steps
- **Dynamic Task Updates**: Adds new tasks based on scan results and findings
- **Scope Enforcement**: Ensures all scans stay within defined target scope
- **Multiple Security Tools**: Integrates with:
  - `nmap`: Network mapping and port scanning
  - `gobuster`: Directory enumeration
  - `ffuf`: Web fuzzing
  - `sqlmap`: SQL injection testing
- **Retry Mechanism**: Automatically retries failed tasks with configurable parameters
- **Beautiful UI**: Streamlit-based interface for easy interaction and monitoring

## Requirements

### Python Version
- Python 3.11 or higher

### System Dependencies
- nmap
- gobuster
- ffuf
- sqlmap

### Python Dependencies
All Python dependencies are managed through Poetry. Main dependencies include:
- langchain
- langgraph
- streamlit
- python-dotenv
- pydantic
- loguru
- pytest (for testing)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/agentic-cybersecurity-pipeline.git
cd agentic-cybersecurity-pipeline
```

2. Install Poetry (if not already installed):
```bash
curl -sSL https://install.python-poetry.org | python3 -
```

3. Install dependencies:
```bash
poetry install
```

4. Install system dependencies:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap gobuster ffuf sqlmap

# Fedora
sudo dnf install nmap gobuster ffuf sqlmap

# Arch Linux
sudo pacman -S nmap gobuster ffuf sqlmap
```

5. Create and configure `.env` file:
```bash
cp .env.example .env
# Edit .env with your settings
```

## Configuration

### Environment Variables
Create a `.env` file with the following variables:
```env
OPENAI_API_KEY=your_openai_api_key
MODEL_NAME=gpt-4
LOG_LEVEL=INFO
```

### Scope Configuration
You can define the scope in two ways:

1. Through the Streamlit UI
2. Using a JSON configuration file:
```json
{
  "allowed_domains": [
    "example.com",
    "*.example.com"
  ],
  "allowed_ips": [
    "192.168.1.0/24",
    "10.0.0.0/8"
  ],
  "excluded_paths": [
    "/admin",
    "/backup"
  ]
}
```

## Usage

### Command Line Interface
```bash
# Basic usage
poetry run python app.py example.com

# With scope configuration
poetry run python app.py example.com --scope-file scope.json

# With manual scope settings
poetry run python app.py example.com \
  --allowed-domains example.com *.example.com \
  --allowed-ips 192.168.1.0/24 \
  --excluded-paths /admin /backup \
  --output results.json
```

### Streamlit Interface
```bash
poetry run streamlit run streamlit_app.py
```

## Architecture

### Components

1. **Security Agent** (`src/agents/security_agent.py`)
   - Uses LangGraph for workflow orchestration
   - Breaks down tasks and manages execution
   - Processes results and updates task list

2. **Task Manager** (`src/agents/task_manager.py`)
   - Handles task execution and retries
   - Manages concurrent task execution
   - Tracks task status and results

3. **Security Tools** (`src/tools/`)
   - `nmap_tool.py`: Network scanning
   - `gobuster_tool.py`: Directory enumeration
   - `ffuf_tool.py`: Web fuzzing
   - `sqlmap_tool.py`: SQL injection testing

4. **Utilities** (`src/utils/`)
   - `scope_validator.py`: Enforces scope constraints
   - `logger.py`: Centralized logging

### Workflow

1. User provides target and scope configuration
2. Security Agent breaks down the task into steps
3. Task Manager executes tasks respecting dependencies
4. Results are processed and new tasks are added as needed
5. Findings are collected and presented to the user

## Testing

Run the test suite:
```bash
poetry run pytest
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Considerations

- Always ensure you have proper authorization before scanning any target
- Use in controlled environments only
- Follow responsible disclosure practices
- Respect scope boundaries and rate limits

## Acknowledgments

- LangChain team for the excellent framework
- Security tool developers (nmap, gobuster, ffuf, sqlmap)
- Streamlit team for the amazing UI framework
