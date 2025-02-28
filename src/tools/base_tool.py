import asyncio
import subprocess
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Union
from ..utils.logger import logger
from ..utils.scope_validator import scope_validator
from ..config.settings import settings

class BaseTool(ABC):
    def __init__(self):
        self.name: str = self.__class__.__name__
        self.timeout: int = settings.DEFAULT_TIMEOUT
        self.max_retries: int = settings.MAX_RETRIES
        self.retry_delay: int = settings.RETRY_DELAY
        
    @abstractmethod
    async def build_command(self, target: str, **kwargs) -> List[str]:
        """Build the command to be executed."""
        pass
        
    @abstractmethod
    async def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse the command output into a structured format."""
        pass
        
    async def validate_target(self, target: str) -> bool:
        """Validate if the target is within scope."""
        return scope_validator.is_target_in_scope(target)
        
    async def execute_command(self, command: List[str]) -> str:
        """Execute a command and return its output."""
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout
            )
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "No error message"
                logger.error(f"{self.name} command failed: {error_msg}")
                raise RuntimeError(f"Command failed with exit code {process.returncode}")
                
            return stdout.decode()
            
        except asyncio.TimeoutError:
            logger.error(f"{self.name} command timed out after {self.timeout} seconds")
            raise
            
        except Exception as e:
            logger.error(f"{self.name} command execution error: {str(e)}")
            raise
            
    async def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Run the tool with retries.
        
        Args:
            target: The target to scan
            **kwargs: Additional arguments for the specific tool
            
        Returns:
            Dict containing the parsed results
        """
        if not await self.validate_target(target):
            raise ValueError(f"Target {target} is not in scope")
            
        retries = 0
        last_error = None
        
        while retries < self.max_retries:
            try:
                command = await self.build_command(target, **kwargs)
                logger.info(f"Running {self.name} command: {' '.join(command)}")
                
                output = await self.execute_command(command)
                results = await self.parse_output(output)
                
                logger.info(f"{self.name} scan completed successfully for {target}")
                return results
                
            except Exception as e:
                last_error = e
                retries += 1
                
                if retries < self.max_retries:
                    logger.warning(
                        f"{self.name} attempt {retries} failed for {target}. "
                        f"Retrying in {self.retry_delay} seconds..."
                    )
                    await asyncio.sleep(self.retry_delay)
                else:
                    logger.error(
                        f"{self.name} failed after {self.max_retries} attempts "
                        f"for {target}: {str(e)}"
                    )
                    
        raise last_error 