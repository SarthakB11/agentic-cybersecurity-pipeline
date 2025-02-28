import json
import re
from typing import List, Dict, Any, Optional
from pathlib import Path
from .base_tool import BaseTool
from ..config.settings import settings

class SQLMapTool(BaseTool):
    def __init__(self):
        super().__init__()
        self.timeout = settings.SQLMAP_TIMEOUT
        self.path = settings.SQLMAP_PATH
        self.output_dir = settings.DATA_DIR / "sqlmap"
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    async def build_command(self, target: str, **kwargs) -> List[str]:
        """Build sqlmap command with specified options."""
        command = [
            self.path,
            "-u", target,
            "--batch",  # Never ask for user input
            "--output-dir", str(self.output_dir),
            "--json-output",
            "-v", "1"  # Verbosity level
        ]
        
        # Add optional arguments
        if data := kwargs.get("data"):
            command.extend(["--data", data])
            
        if method := kwargs.get("method"):
            command.extend(["--method", method])
            
        if cookie := kwargs.get("cookie"):
            command.extend(["--cookie", cookie])
            
        if headers := kwargs.get("headers"):
            for header in headers:
                command.extend(["--header", header])
                
        # Add technique specification if provided
        if techniques := kwargs.get("techniques", "BEUSTQ"):
            command.extend(["--technique", techniques])
            
        # Add risk and level settings
        risk = kwargs.get("risk", "1")
        level = kwargs.get("level", "1")
        command.extend(["--risk", str(risk), "--level", str(level)])
        
        # Add database options
        if dbms := kwargs.get("dbms"):
            command.extend(["--dbms", dbms])
            
        if db := kwargs.get("db"):
            command.extend(["-D", db])
            
        if table := kwargs.get("table"):
            command.extend(["-T", table])
            
        if column := kwargs.get("column"):
            command.extend(["-C", column])
            
        # Add advanced options
        if kwargs.get("dump", False):
            command.append("--dump")
            
        if kwargs.get("dump_all", False):
            command.append("--dump-all")
            
        if kwargs.get("forms", False):
            command.append("--forms")
            
        if kwargs.get("crawl", False):
            command.append("--crawl")
            
        if threads := kwargs.get("threads", "1"):
            command.extend(["--threads", str(threads)])
            
        return command
        
    async def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap output into structured data."""
        result = {
            "vulnerable": False,
            "database_type": None,
            "vulnerabilities": [],
            "databases": [],
            "tables": [],
            "columns": [],
            "data": [],
            "error": None
        }
        
        try:
            # Look for JSON output in the sqlmap results directory
            json_files = list(self.output_dir.glob("*.json"))
            if not json_files:
                # If no JSON file found, parse the text output
                return self._parse_text_output(output)
                
            # Read the most recent JSON file
            latest_json = max(json_files, key=lambda x: x.stat().st_mtime)
            with open(latest_json) as f:
                data = json.load(f)
                
            # Parse the JSON data
            if data.get("success", False):
                result["vulnerable"] = True
                
            if data.get("data", []):
                for item in data["data"]:
                    if "type" in item:
                        result["database_type"] = item["type"]
                        
                    if "value" in item:
                        if isinstance(item["value"], list):
                            result["data"].extend(item["value"])
                        else:
                            result["data"].append(item["value"])
                            
            if data.get("techniques", []):
                result["vulnerabilities"].extend(data["techniques"])
                
            if data.get("dbs", []):
                result["databases"] = data["dbs"]
                
            # Extract tables and columns if available
            if data.get("tables", {}):
                for db, tables in data["tables"].items():
                    for table in tables:
                        result["tables"].append({"database": db, "table": table})
                        
            if data.get("columns", {}):
                for db, tables in data["columns"].items():
                    for table, columns in tables.items():
                        result["columns"].append({
                            "database": db,
                            "table": table,
                            "columns": columns
                        })
                        
            return result
            
        except Exception as e:
            result["error"] = str(e)
            return result
            
    def _parse_text_output(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap text output when JSON is not available."""
        result = {
            "vulnerable": False,
            "database_type": None,
            "vulnerabilities": [],
            "error": None
        }
        
        try:
            # Check if target is vulnerable
            if "is vulnerable to" in output:
                result["vulnerable"] = True
                
            # Try to identify database type
            db_types = ["MySQL", "PostgreSQL", "Microsoft SQL Server", "Oracle", "SQLite"]
            for db_type in db_types:
                if db_type.lower() in output.lower():
                    result["database_type"] = db_type
                    break
                    
            # Extract vulnerability types
            vuln_patterns = [
                r"Type: ([^\n]+)",
                r"Title: ([^\n]+)",
                r"Payload: ([^\n]+)"
            ]
            
            for pattern in vuln_patterns:
                matches = re.finditer(pattern, output)
                for match in matches:
                    if match.group(1) not in result["vulnerabilities"]:
                        result["vulnerabilities"].append(match.group(1))
                        
            return result
            
        except Exception as e:
            result["error"] = str(e)
            return result

# Create singleton instance
sqlmap_tool = SQLMapTool()
