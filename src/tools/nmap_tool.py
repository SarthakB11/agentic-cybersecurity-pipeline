import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from .base_tool import BaseTool
from ..config.settings import settings

class NmapTool(BaseTool):
    def __init__(self):
        super().__init__()
        self.timeout = settings.NMAP_TIMEOUT
        self.path = settings.NMAP_PATH
        
    async def build_command(self, target: str, **kwargs) -> List[str]:
        """Build nmap command with specified options."""
        command = [
            self.path,
            "-sV",  # Version detection
            "-sC",  # Default script scan
            "-oX", "-",  # Output in XML format to stdout
            "--open",  # Only show open ports
        ]
        
        # Add optional arguments
        ports = kwargs.get("ports")
        if ports:
            command.extend(["-p", str(ports)])
            
        timing = kwargs.get("timing", "4")
        command.extend([f"-T{timing}"])
        
        if kwargs.get("aggressive", False):
            command.append("-A")
            
        if kwargs.get("no_ping", False):
            command.append("-Pn")
            
        command.append(target)
        return command
        
    async def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap XML output into structured data."""
        try:
            root = ET.fromstring(output)
            result = {
                "target": "",
                "start_time": "",
                "end_time": "",
                "hosts": []
            }
            
            # Get scan information
            if run := root.find("runstats/finished"):
                result["end_time"] = run.get("timestr", "")
                
            if start := root.find("runstats/started"):
                result["start_time"] = start.get("timestr", "")
                
            # Process each host
            for host in root.findall("host"):
                host_info = {
                    "address": "",
                    "hostnames": [],
                    "ports": []
                }
                
                # Get IP address
                if addr := host.find("address[@addrtype='ipv4']"):
                    host_info["address"] = addr.get("addr", "")
                    
                # Get hostnames
                for hostname in host.findall("hostnames/hostname"):
                    host_info["hostnames"].append(hostname.get("name", ""))
                    
                # Get ports information
                for port in host.findall("ports/port"):
                    port_info = {
                        "protocol": port.get("protocol", ""),
                        "portid": port.get("portid", ""),
                        "state": "",
                        "service": {
                            "name": "",
                            "product": "",
                            "version": "",
                            "extrainfo": ""
                        }
                    }
                    
                    if state := port.find("state"):
                        port_info["state"] = state.get("state", "")
                        
                    if service := port.find("service"):
                        port_info["service"].update({
                            "name": service.get("name", ""),
                            "product": service.get("product", ""),
                            "version": service.get("version", ""),
                            "extrainfo": service.get("extrainfo", "")
                        })
                        
                    if port_info["state"] == "open":
                        host_info["ports"].append(port_info)
                        
                result["hosts"].append(host_info)
                
            return result
            
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse nmap output: {str(e)}")
            
        except Exception as e:
            raise RuntimeError(f"Error processing nmap output: {str(e)}")

# Create singleton instance
nmap_tool = NmapTool()
