from typing import List, Optional
import ipaddress
from urllib.parse import urlparse
from ..config.settings import settings
from .logger import logger

class ScopeValidator:
    """Validates if targets are within the defined scope."""
    
    def __init__(self):
        self.allowed_domains: List[str] = []
        self.allowed_ips: List[str] = []
        self.excluded_paths: List[str] = []
        self.load_default_scope()
    
    def load_default_scope(self):
        """Load default scope from settings."""
        self.allowed_domains = settings.ALLOWED_DOMAINS
        self.allowed_ips = [ip for ip in settings.ALLOWED_IPS]
        self.excluded_paths = settings.EXCLUDED_PATHS
    
    def update_scope(self, scope: dict):
        """Update scope with new configuration."""
        self.allowed_domains = scope.get("allowed_domains", self.allowed_domains)
        self.allowed_ips = scope.get("allowed_ips", self.allowed_ips)
        self.excluded_paths = scope.get("excluded_paths", self.excluded_paths)
    
    def is_domain_in_scope(self, domain: str) -> bool:
        """Check if a domain is in the allowed list."""
        domain = domain.lower()
        return any(
            domain == allowed.lower() or
            (allowed.startswith("*.") and domain.endswith(allowed[2:].lower()))
            for allowed in self.allowed_domains
        )
    
    def is_ip_in_scope(self, ip: str) -> bool:
        """Check if an IP is in the allowed ranges."""
        try:
            target_ip = ipaddress.ip_address(ip)
            return any(
                target_ip in ipaddress.ip_network(network)
                for network in self.allowed_ips
            )
        except ValueError:
            return False
    
    def is_path_excluded(self, path: str) -> bool:
        """Check if a path matches any excluded patterns."""
        return any(
            excluded in path
            for excluded in self.excluded_paths
        )
    
    async def validate_target(self, target: str) -> bool:
        """Validate if a target is within scope."""
        # Parse the target
        parsed = urlparse(target if "://" in target else f"http://{target}")
        
        # Extract domain/IP
        hostname = parsed.hostname or target
        
        # Check if it's an IP
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False
            
        # Validate based on type
        if is_ip:
            if not self.is_ip_in_scope(hostname):
                return False
        else:
            if not self.is_domain_in_scope(hostname):
                return False
                
        # Check path if present
        if parsed.path and self.is_path_excluded(parsed.path):
            return False
            
        return True
    
    async def validate_targets(self, targets: List[str]) -> List[str]:
        """Validate multiple targets."""
        valid_targets = []
        for target in targets:
            if await self.validate_target(target):
                valid_targets.append(target)
        return valid_targets

# Create singleton instance
scope_validator = ScopeValidator()
