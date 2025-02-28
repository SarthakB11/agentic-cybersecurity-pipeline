from typing import List, Union
import ipaddress
from urllib.parse import urlparse
from ..config.settings import settings
from .logger import logger

class ScopeValidator:
    def __init__(self):
        self.allowed_domains = settings.ALLOWED_DOMAINS
        self.allowed_ips = [ipaddress.ip_network(ip) for ip in settings.ALLOWED_IPS]
        self.excluded_paths = settings.EXCLUDED_PATHS
    
    def is_domain_in_scope(self, domain: str) -> bool:
        """Check if a domain is within the allowed scope."""
        try:
            # Remove protocol and path if present
            parsed = urlparse(domain)
            domain = parsed.netloc if parsed.netloc else parsed.path
            domain = domain.split(':')[0]  # Remove port if present
            
            # Check if domain matches any allowed domain pattern
            return any(
                domain == allowed or
                (allowed.startswith('.') and domain.endswith(allowed)) or
                (allowed.startswith('*.') and domain.endswith(allowed[1:]))
                for allowed in self.allowed_domains
            )
        except Exception as e:
            logger.error(f"Error validating domain scope for {domain}: {str(e)}")
            return False
    
    def is_ip_in_scope(self, ip: str) -> bool:
        """Check if an IP address is within the allowed scope."""
        try:
            target_ip = ipaddress.ip_address(ip)
            return any(target_ip in network for network in self.allowed_ips)
        except Exception as e:
            logger.error(f"Error validating IP scope for {ip}: {str(e)}")
            return False
    
    def is_path_excluded(self, path: str) -> bool:
        """Check if a path matches any excluded patterns."""
        return any(
            excluded in path
            for excluded in self.excluded_paths
        )
    
    def is_target_in_scope(self, target: str) -> bool:
        """
        Check if a target (domain or IP) is within the allowed scope
        and not in excluded paths.
        """
        if self.is_path_excluded(target):
            logger.warning(f"Target {target} matches excluded path pattern")
            return False
            
        try:
            # Try parsing as IP first
            ipaddress.ip_address(target)
            return self.is_ip_in_scope(target)
        except ValueError:
            # If not IP, treat as domain
            return self.is_domain_in_scope(target)
    
    def validate_targets(self, targets: Union[str, List[str]]) -> List[str]:
        """
        Validate a list of targets and return only those within scope.
        
        Args:
            targets: Single target string or list of target strings
            
        Returns:
            List of targets that are within scope
        """
        if isinstance(targets, str):
            targets = [targets]
            
        in_scope = []
        for target in targets:
            if self.is_target_in_scope(target):
                in_scope.append(target)
            else:
                logger.warning(f"Target {target} is out of scope")
                
        return in_scope

# Create singleton instance
scope_validator = ScopeValidator()
