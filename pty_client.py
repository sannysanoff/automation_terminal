#!/usr/bin/env python3
"""
Python client for the PTY Automation Terminal Server.
Provides a CLI interface to interact with all REST endpoints.
"""

import argparse
import json
import sys
import requests
from typing import Dict, Any, Optional


class PTYClient:
    """Client for interacting with the PTY Automation Terminal Server."""
    
    def __init__(self, host: str = "localhost", port: int = 5399):
        """Initialize the client with server connection details."""
        self.base_url = f"http://{host}:{port}"
        self.session = requests.Session()
    
    def sendkeys_nowait(self, keys: str) -> Dict[str, Any]:
        """Send keystroke to the terminal (async)."""
        url = f"{self.base_url}/sendkeys_nowait"
        data = {"keys": keys}
        
        try:
            response = self.session.post(url, data=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}
    
    def sendkeys(self, keys: str) -> Dict[str, Any]:
        """Send keystroke to the terminal and wait for completion (sync)."""
        url = f"{self.base_url}/sendkeys"
        data = {"keys": keys}
        
        try:
            response = self.session.post(url, data=data, timeout=60)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}
    
    def get_screen(self) -> Dict[str, Any]:
        """Get current screen content and cursor position."""
        url = f"{self.base_url}/screen"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}
    
    def oob_exec(self, cmd: str) -> Dict[str, Any]:
        """Execute command out-of-band (outside the PTY)."""
        url = f"{self.base_url}/oob_exec"
        data = {"cmd": cmd}
        
        try:
            response = self.session.post(url, data=data, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}


def format_sendkeys_nowait_response(response: Dict[str, Any]) -> str:
    """Format sendkeys_nowait response for display."""
    if "error" in response:
        return f"❌ Error: {response['error']}"
    
    status = response.get("status", "unknown")
    keys_sent = response.get("keys_sent", "")
    
    if status == "success":
        return f"✅ Keys sent successfully: {repr(keys_sent)}"
    else:
        return f"⚠️  Status: {status}, Keys: {repr(keys_sent)}"


def format_sendkeys_response(response: Dict[str, Any]) -> str:
    """Format sendkeys response for display."""
    if "error" in response:
        return f"❌ Error: {response['error']}"
    
    status = response.get("status", "unknown")
    message = response.get("message", "")
    output = response.get("output", "")
    timeout = response.get("timeout", False)
    
    result = []
    
    if status == "success":
        result.append("✅ Command completed successfully")
    elif status == "timeout":
        result.append("⏰ Command timed out")
    else:
        result.append(f"⚠️  Status: {status}")
    
    if message:
        result.append(f"Message: {message}")
    
    if timeout:
        result.append("⚠️  Operation timed out")
    
    if output:
        result.append("\n--- Command Output ---")
        result.append(output)
        result.append("--- End Output ---")
    
    return "\n".join(result)


def format_screen_response(response: Dict[str, Any]) -> str:
    """Format screen response for display."""
    if "error" in response:
        return f"❌ Error: {response['error']}"
    
    screen = response.get("screen", [])
    cursor = response.get("cursor", {})
    
    result = []
    result.append("📺 Current Screen Content:")
    result.append("=" * 80)
    
    for i, line in enumerate(screen):
        # Show line numbers for reference
        result.append(f"{i:2d}│{line}")
    
    result.append("=" * 80)
    
    cursor_x = cursor.get("x", 0)
    cursor_y = cursor.get("y", 0)
    cursor_hidden = cursor.get("hidden", False)
    
    cursor_status = "hidden" if cursor_hidden else "visible"
    result.append(f"🖱️  Cursor: ({cursor_x}, {cursor_y}) - {cursor_status}")
    
    return "\n".join(result)


def format_oob_exec_response(response: Dict[str, Any]) -> str:
    """Format oob_exec response for display."""
    if "error" in response:
        return f"❌ Error: {response['error']}"
    
    stdout = response.get("stdout", "")
    stderr = response.get("stderr", "")
    exit_code = response.get("exit_code", 0)
    timeout = response.get("timeout", False)
    
    result = []
    
    if timeout:
        result.append("⏰ Command timed out")
    elif exit_code == 0:
        result.append("✅ Command executed successfully")
    else:
        result.append(f"❌ Command failed with exit code: {exit_code}")
    
    if stdout:
        result.append("\n--- STDOUT ---")
        result.append(stdout)
    
    if stderr:
        result.append("\n--- STDERR ---")
        result.append(stderr)
    
    if stdout or stderr:
        result.append("--- End Output ---")
    
    return "\n".join(result)


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="PTY Automation Terminal Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s sendkeys-nowait "ls -la\\n"
  %(prog)s sendkeys "echo 'Hello World'\\n"
  %(prog)s screen
  %(prog)s oob-exec "ps aux | grep python"
  %(prog)s --host 192.168.1.100 --port 5399 screen
        """
    )
    
    parser.add_argument(
        "--host", 
        default="localhost", 
        help="Server host (default: localhost)"
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=5399, 
        help="Server port (default: 5399)"
    )
    parser.add_argument(
        "--json", 
        action="store_true", 
        help="Output raw JSON response"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Sendkeys nowait command
    sendkeys_nowait_parser = subparsers.add_parser(
        "sendkeys-nowait", 
        help="Send keystroke to terminal (async)"
    )
    sendkeys_nowait_parser.add_argument(
        "keys", 
        help="Keys to send (use \\n for newline, \\t for tab)"
    )
    
    # Sendkeys command
    sendkeys_parser = subparsers.add_parser(
        "sendkeys", 
        help="Send keystroke to terminal and wait for completion (sync)"
    )
    sendkeys_parser.add_argument(
        "keys", 
        help="Keys to send (use \\n for newline, \\t for tab)"
    )
    
    # Screen command
    subparsers.add_parser(
        "screen", 
        help="Get current screen content and cursor position"
    )
    
    # OOB exec command
    oob_exec_parser = subparsers.add_parser(
        "oob-exec", 
        help="Execute command out-of-band (outside PTY)"
    )
    oob_exec_parser.add_argument(
        "cmd", 
        help="Command to execute"
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Create client
    client = PTYClient(host=args.host, port=args.port)
    
    # Execute command
    try:
        if args.command == "sendkeys-nowait":
            # Process escape sequences
            keys = args.keys.encode().decode('unicode_escape')
            response = client.sendkeys_nowait(keys)
            if args.json:
                print(json.dumps(response, indent=2))
            else:
                print(format_sendkeys_nowait_response(response))
        
        elif args.command == "sendkeys":
            # Process escape sequences
            keys = args.keys.encode().decode('unicode_escape')
            response = client.sendkeys(keys)
            if args.json:
                print(json.dumps(response, indent=2))
            else:
                print(format_sendkeys_response(response))
        
        elif args.command == "screen":
            response = client.get_screen()
            if args.json:
                print(json.dumps(response, indent=2))
            else:
                print(format_screen_response(response))
        
        elif args.command == "oob-exec":
            response = client.oob_exec(args.cmd)
            if args.json:
                print(json.dumps(response, indent=2))
            else:
                print(format_oob_exec_response(response))
    
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
