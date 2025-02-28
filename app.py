import asyncio
import argparse
from typing import Dict, Any
import json
from pathlib import Path

from src.agents.security_agent import security_agent
from src.utils.logger import logger
from src.config.settings import settings

async def main(args: argparse.Namespace) -> None:
    """Main application entry point."""
    try:
        # Load scope configuration
        if args.scope_file:
            with open(args.scope_file) as f:
                scope = json.load(f)
        else:
            scope = {
                "allowed_domains": args.allowed_domains or [],
                "allowed_ips": args.allowed_ips or [],
                "excluded_paths": args.excluded_paths or []
            }
            
        # Update settings if provided
        if args.max_retries:
            settings.MAX_RETRIES = args.max_retries
            
        if args.openai_api_key:
            settings.OPENAI_API_KEY = args.openai_api_key
            
        # Run security audit
        logger.info(f"Starting security audit of {args.target}")
        results = await security_agent.run_security_audit(args.target, scope)
        
        # Save results if output file specified
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, "w") as f:
                json.dump(results, f, indent=2)
                logger.info(f"Results saved to {output_path}")
                
        # Print summary
        print("\nAudit Summary:")
        print("-" * 50)
        print(f"Target: {args.target}")
        print(f"Total Tasks: {len(results['results'])}")
        print(f"Completed: {sum(1 for r in results['results'].values() if r['status'] == 'completed')}")
        print(f"Failed: {sum(1 for r in results['results'].values() if r['status'] == 'failed')}")
        
        if results["errors"]:
            print("\nErrors:")
            for error in results["errors"]:
                print(f"- {error}")
                
    except Exception as e:
        logger.error(f"Error in security audit: {str(e)}")
        raise

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Agentic Security Testing Pipeline"
    )
    
    parser.add_argument(
        "target",
        help="Target URL or IP address to audit"
    )
    
    parser.add_argument(
        "--scope-file",
        help="JSON file containing scope configuration"
    )
    
    parser.add_argument(
        "--allowed-domains",
        nargs="+",
        help="List of allowed domains"
    )
    
    parser.add_argument(
        "--allowed-ips",
        nargs="+",
        help="List of allowed IP ranges"
    )
    
    parser.add_argument(
        "--excluded-paths",
        nargs="+",
        help="List of excluded paths"
    )
    
    parser.add_argument(
        "--max-retries",
        type=int,
        help="Maximum number of retries for failed tasks"
    )
    
    parser.add_argument(
        "--output",
        help="Output file to save results (JSON format)"
    )
    
    parser.add_argument(
        "--openai-api-key",
        help="OpenAI API key for LangChain"
    )
    
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    asyncio.run(main(args))
