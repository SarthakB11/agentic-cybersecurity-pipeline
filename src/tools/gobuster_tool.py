import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from .base_tool import BaseTool
from ..config.settings import settings

class GobusterTool(BaseTool):
    def __init__(self):
        super().__init__()
        self.timeout = settings.GOBUSTER_TIMEOUT
        self.path = settings.GOBUSTER_PATH
        self.wordlists_dir = settings.DATA_DIR / "wordlists"
        self.default_wordlist = self.wordlists_dir / "directory-list-2.3-medium.txt"
        
        # Ensure wordlists directory exists
        self.wordlists_dir.mkdir(parents=True, exist_ok=True)
        
    async def build_command(self, target: str, **kwargs) -> List[str]:
        """Build gobuster command with specified options."""
        wordlist = kwargs.get("wordlist", self.default_wordlist)
        
        command = [
            self.path,
            "dir",  # Directory enumeration mode
            "-u", target,
            "-w", str(wordlist),
            "-o", "-",  # Output to stdout
            "-q",  # Quiet mode
            "--no-error",
        ]
        
        # Add optional arguments
        if extensions := kwargs.get("extensions"):
            command.extend(["-x", extensions])
            
        if status_codes := kwargs.get("status_codes"):
            command.extend(["-s", status_codes])
            
        if threads := kwargs.get("threads", "10"):
            command.extend(["-t", str(threads)])
            
        if kwargs.get("follow_redirects", False):
            command.append("-r")
            
        if kwargs.get("expanded", False):
            command.append("-e")
            
        # Add custom headers if provided
        if headers := kwargs.get("headers"):
            for header in headers:
                command.extend(["-H", header])
                
        return command
        
    async def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse gobuster output into structured data."""
        result = {
            "directories": [],
            "files": [],
            "total_found": 0
        }
        
        try:
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                    
                # Parse each line (format: "URL (Status: XXX) [Size: YYY]")
                parts = line.split()
                if len(parts) < 3:
                    continue
                    
                url = parts[0]
                status = None
                size = None
                
                # Extract status code
                status_part = next((p for p in parts if p.startswith("(Status:")), None)
                if status_part:
                    status = status_part.strip("(Status:)")
                    
                # Extract size
                size_part = next((p for p in parts if p.startswith("[Size:")), None)
                if size_part:
                    size = size_part.strip("[Size:]").strip("]")
                    
                entry = {
                    "url": url,
                    "status_code": status,
                    "size": size
                }
                
                # Categorize as directory or file
                if url.endswith("/"):
                    result["directories"].append(entry)
                else:
                    result["files"].append(entry)
                    
            result["total_found"] = len(result["directories"]) + len(result["files"])
            return result
            
        except Exception as e:
            raise RuntimeError(f"Error processing gobuster output: {str(e)}")

# Create singleton instance
gobuster_tool = GobusterTool()
