import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from .base_tool import BaseTool
from ..config.settings import settings

class FFufTool(BaseTool):
    def __init__(self):
        super().__init__()
        self.timeout = settings.FFUF_TIMEOUT
        self.path = settings.FFUF_PATH
        self.wordlists_dir = settings.DATA_DIR / "wordlists"
        self.default_wordlist = self.wordlists_dir / "common.txt"
        
        # Ensure wordlists directory exists
        self.wordlists_dir.mkdir(parents=True, exist_ok=True)
        
    async def build_command(self, target: str, **kwargs) -> List[str]:
        """Build ffuf command with specified options."""
        wordlist = kwargs.get("wordlist", self.default_wordlist)
        
        command = [
            self.path,
            "-u", f"{target}/FUZZ",
            "-w", str(wordlist),
            "-o", "-",  # Output to stdout
            "-of", "json",  # JSON output format
            "-s",  # Silent mode
        ]
        
        # Add optional arguments
        if methods := kwargs.get("methods"):
            command.extend(["-X", methods])
            
        if extensions := kwargs.get("extensions"):
            command.extend(["-e", extensions])
            
        if threads := kwargs.get("threads", "40"):
            command.extend(["-t", str(threads)])
            
        if mc := kwargs.get("match_codes"):
            command.extend(["-mc", mc])
            
        if ms := kwargs.get("match_size"):
            command.extend(["-ms", ms])
            
        if mw := kwargs.get("match_words"):
            command.extend(["-mw", mw])
            
        # Add custom headers if provided
        if headers := kwargs.get("headers"):
            for header in headers:
                command.extend(["-H", header])
                
        # Add proxy if provided
        if proxy := kwargs.get("proxy"):
            command.extend(["-x", proxy])
            
        # Add delay between requests if provided
        if delay := kwargs.get("delay"):
            command.extend(["-p", str(delay)])
            
        return command
        
    async def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse ffuf JSON output into structured data."""
        try:
            data = json.loads(output)
            result = {
                "results": [],
                "statistics": {
                    "total_requests": 0,
                    "total_time": 0,
                    "req_per_sec": 0
                }
            }
            
            # Extract results
            if "results" in data:
                for entry in data["results"]:
                    result["results"].append({
                        "url": entry.get("url", ""),
                        "status": entry.get("status", 0),
                        "length": entry.get("length", 0),
                        "words": entry.get("words", 0),
                        "lines": entry.get("lines", 0),
                        "content_type": entry.get("content-type", ""),
                        "redirect_location": entry.get("redirectlocation", "")
                    })
                    
            # Extract statistics
            if "stats" in data:
                stats = data["stats"]
                result["statistics"].update({
                    "total_requests": stats.get("total", 0),
                    "total_time": stats.get("total_time", 0),
                    "req_per_sec": stats.get("req_per_sec", 0)
                })
                
            return result
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse ffuf JSON output: {str(e)}")
            
        except Exception as e:
            raise RuntimeError(f"Error processing ffuf output: {str(e)}")

# Create singleton instance
ffuf_tool = FFufTool()
