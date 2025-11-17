"""
Bitwarden CLI-based MCP Server Client

This module provides a client for interacting with Bitwarden/Vaultwarden
via the Bitwarden CLI (bw) for password management and secure notes.
"""

import subprocess
import json
import logging
import os
import pexpect
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@dataclass
class BitwardenItem:
    """Represents a Bitwarden item (password, note, etc.)"""
    id: str
    name: str
    username: Optional[str] = None
    password: Optional[str] = None
    uris: List[str] = None
    notes: Optional[str] = None
    folder_id: Optional[str] = None
    type: int = 1  # 1=Login, 2=SecureNote, 3=Card, 4=Identity
    favorite: bool = False

    def __post_init__(self):
        if self.uris is None:
            self.uris = []


class BitwardenCLIClient:
    """Client for Bitwarden using the bw CLI tool."""
    
    def __init__(self, base_url: str, email: str, password: str, 
                 client_id: str = "bitwarden-mcp-server", 
                 client_secret: str = "bitwarden-mcp-secret"):
        """Initialize the Bitwarden CLI client.
        
        Args:
            base_url: Bitwarden/Vaultwarden server URL
            email: User email
            password: User password
            client_id: Client ID for API authentication (optional)
            client_secret: Client secret for API authentication (optional)
        """
        self.base_url = base_url.rstrip('/')
        self.email = email
        self.password = password
        self.client_id = client_id
        self.client_secret = client_secret
        self.session_key = None
        
        # Set environment variables for bw CLI
        os.environ['BW_SERVER'] = self.base_url
        os.environ['BW_CLIENTSECRET'] = self.client_secret
        
    def _run_bw_command(self, command: List[str], input_data: str = None) -> Dict[str, Any]:
        """Run a bw CLI command and return the JSON response.
        
        Args:
            command: List of command arguments
            input_data: Input data to send to stdin
            
        Returns:
            JSON response from bw CLI
        """
        try:
            # Set environment for TLS issues with Vaultwarden
            env = os.environ.copy()
            env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'
            
            logger.debug(f"Running bw command: {' '.join(command)}")
            
            # Use env command to set NODE_TLS_REJECT_UNAUTHORIZED=0
            process = subprocess.run(
                ['env', 'NODE_TLS_REJECT_UNAUTHORIZED=0', 'bw'] + command,
                input=input_data,
                text=True,
                capture_output=True,
                timeout=30,
                env=env
            )
            
            logger.debug(f"bw exit code: {process.returncode}")
            logger.debug(f"bw stdout: {process.stdout[:500]}")
            if process.stderr:
                logger.debug(f"bw stderr: {process.stderr[:500]}")
            
            if process.returncode != 0:
                error_msg = process.stderr or process.stdout or "Unknown error"
                raise Exception(f"bw command failed: {error_msg}")
            
            if process.stdout.strip():
                try:
                    return json.loads(process.stdout)
                except json.JSONDecodeError:
                    # Some commands return plain text (like config server)
                    return {"message": process.stdout.strip()}
            return {}
            
        except subprocess.TimeoutExpired:
            raise Exception("bw command timed out")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse bw output as JSON: {e}")
            logger.error(f"Raw output: {process.stdout}")
            raise Exception(f"Invalid JSON response from bw: {e}")
        except Exception as e:
            logger.error(f"bw command error: {str(e)}")
            raise Exception(f"bw command failed: {str(e)}")
    
    def authenticate(self) -> bool:
        """Authenticate with Bitwarden/Vaultwarden using bw CLI.
        
        Returns:
            True if authentication successful, False otherwise
        """
        try:
            # First logout if already logged in
            try:
                self._run_bw_command(['logout'])
            except:
                pass  # Ignore logout errors
            
            # Configure server
            self._run_bw_command(['config', 'server', self.base_url])
            
            # Login using pexpect for interactive input
            logger.debug("Starting interactive login with pexpect")
            child = pexpect.spawn('env', ['NODE_TLS_REJECT_UNAUTHORIZED=0', 'bw', 'login', '--raw'], timeout=30)
            
            # Wait for email prompt and send email
            child.expect('Email address:')
            child.sendline(self.email)
            
            # Wait for password prompt and send password
            child.expect('Master password:')
            child.sendline(self.password)
            
            # Wait for completion and get output
            child.expect(pexpect.EOF)
            output = child.before.decode('utf-8')
            child.close()
            
            # Check if we got a session key
            if output and len(output.strip()) > 10:
                self.session_key = output.strip()
                logger.info("Successfully authenticated with Bitwarden")
                return True
            else:
                logger.error(f"Authentication failed - no session key received. Output: {output}")
                return False
                
        except pexpect.TIMEOUT:
            logger.error("Authentication timed out")
            return False
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False
    
    def logout(self) -> bool:
        """Logout from Bitwarden.
        
        Returns:
            True if logout successful, False otherwise
        """
        try:
            self._run_bw_command(['logout'])
            self.session_key = None
            logger.info("Successfully logged out from Bitwarden")
            return True
        except Exception as e:
            logger.error(f"Logout failed: {str(e)}")
            return False

    def unlock_vault(self) -> bool:
        """Unlock the Bitwarden vault and get session key.
        
        Returns:
            True if unlock successful, False otherwise
        """
        try:
            logger.debug("Unlocking vault with pexpect")
            child = pexpect.spawn('env', ['NODE_TLS_REJECT_UNAUTHORIZED=0', 'bw', 'unlock', '--raw'], timeout=30)
            
            # Wait for password prompt and send password
            child.expect('Master password:')
            child.sendline(self.password)
            
            # Wait for completion and get output
            child.expect(pexpect.EOF)
            output = child.before.decode('utf-8')
            child.close()
            
            # Check if we got a session key
            if output and len(output.strip()) > 10:
                self.session_key = output.strip()
                logger.info("Vault unlocked successfully")
                return True
            else:
                logger.error(f"Unlock failed - no session key received. Output: {output}")
                return False
                
        except pexpect.TIMEOUT:
            logger.error("Unlock timed out")
            return False
        except Exception as e:
            logger.error(f"Unlock failed: {str(e)}")
            return False
    
    def _ensure_logged_in(self) -> bool:
        """Ensure we're logged in to Bitwarden.
        
        Returns:
            True if logged in, False otherwise
        """
        try:
            # Check if we're already logged in
            result = self._run_bw_command(['status'])
            if result and result.get('status') == 'authenticated':
                return True
            
            # If not logged in, try to login
            logger.info("Not logged in, attempting to login...")
            return self.authenticate()
            
        except Exception as e:
            logger.error(f"Failed to check login status: {str(e)}")
            return False
    
    def search_items(self, query: str = None, item_type: str = None, 
                    folder_id: str = None, limit: int = 20) -> List[BitwardenItem]:
        """Search for Bitwarden items.
        
        Args:
            query: Search term
            item_type: Item type filter (login, note, card, identity)
            folder_id: Folder ID filter
            limit: Maximum number of results
            
        Returns:
            List of BitwardenItem objects
        """
        try:
            # Ensure we're logged in first
            if not self._ensure_logged_in():
                logger.error("Not logged in, cannot search items")
                return []
            
            # Build search command
            cmd = ['list', 'items']
            
            if query:
                cmd.extend(['--search', query])
            
            if item_type:
                type_map = {
                    'login': '1',
                    'note': '2', 
                    'card': '3',
                    'identity': '4'
                }
                if item_type.lower() in type_map:
                    cmd.extend(['--type', type_map[item_type.lower()]])
            
            if folder_id:
                cmd.extend(['--folderid', folder_id])
            
            # Use pexpect for interactive password prompt
            logger.debug(f"Running bw command with pexpect: {' '.join(cmd)}")
            child = pexpect.spawn('env', ['NODE_TLS_REJECT_UNAUTHORIZED=0', 'bw'] + cmd, timeout=30)
            
            # Wait for password prompt and send password
            child.expect('Master password:')
            child.sendline(self.password)
            
            # Wait for completion and get output
            child.expect(pexpect.EOF)
            output = child.before.decode('utf-8')
            child.close()
            
            # Parse JSON output
            if output.strip():
                try:
                    items_data = json.loads(output)
                    items = items_data.get('data', []) if isinstance(items_data, dict) else items_data
                    
                    # Convert to BitwardenItem objects
                    result = []
                    for item in items[:limit]:
                        bw_item = self._parse_item(item)
                        if bw_item:
                            result.append(bw_item)
                    
                    return result
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse JSON output: {output}")
                    return []
            return []
            
        except pexpect.TIMEOUT:
            logger.error("Search items timed out")
            return []
        except Exception as e:
            logger.error(f"Search failed: {str(e)}")
            return []
    
    def get_item(self, item_id: str) -> Optional[BitwardenItem]:
        """Get a specific Bitwarden item by ID.
        
        Args:
            item_id: Item ID
            
        Returns:
            BitwardenItem object or None if not found
        """
        try:
            cmd = ['get', 'item', item_id]
            if self.session_key:
                cmd.extend(['--session', self.session_key])
            
            item_data = self._run_bw_command(cmd)
            
            if item_data:
                return self._parse_item(item_data)
            return None
            
        except Exception as e:
            logger.error(f"Get item failed: {str(e)}")
            return None
    
    def create_login(self, name: str, username: str, password: str, 
                    uris: List[str] = None, notes: str = None, 
                    folder_id: str = None) -> Optional[str]:
        """Create a new login item.
        
        Args:
            name: Item name
            username: Username
            password: Password
            uris: List of URLs
            notes: Notes
            folder_id: Folder ID
            
        Returns:
            Created item ID or None if failed
        """
        try:
            # Create item template
            item_template = {
                "type": 1,  # Login
                "name": name,
                "login": {
                    "username": username,
                    "password": password,
                    "uris": [{"uri": uri} for uri in (uris or [])]
                },
                "notes": notes or ""
            }
            
            if folder_id:
                item_template["folderId"] = folder_id
            
            # Encode the item data
            encode_result = self._run_bw_command(['encode'], json.dumps(item_template))
            encoded_data = encode_result.get('message', '') if isinstance(encode_result, dict) else str(encode_result)
            
            # Create item with encoded data
            cmd = ['create', 'item']
            if self.session_key:
                cmd.extend(['--session', self.session_key])
            
            result = self._run_bw_command(cmd, encoded_data)
            
            if result and 'id' in result:
                return result['id']
            return None
            
        except Exception as e:
            logger.error(f"Create login failed: {str(e)}")
            return None
    
    def create_note(self, name: str, content: str, folder_id: str = None) -> Optional[str]:
        """Create a new secure note.
        
        Args:
            name: Note name
            content: Note content
            folder_id: Folder ID
            
        Returns:
            Created item ID or None if failed
        """
        try:
            # Create note template
            item_template = {
                "type": 2,  # SecureNote
                "name": name,
                "secureNote": {
                    "type": 0  # Generic
                },
                "notes": content
            }
            
            if folder_id:
                item_template["folderId"] = folder_id
            
            # Encode the item data
            encode_result = self._run_bw_command(['encode'], json.dumps(item_template))
            encoded_data = encode_result.get('message', '') if isinstance(encode_result, dict) else str(encode_result)
            
            # Create item with encoded data
            cmd = ['create', 'item']
            if self.session_key:
                cmd.extend(['--session', self.session_key])
            
            result = self._run_bw_command(cmd, encoded_data)
            
            if result and 'id' in result:
                return result['id']
            return None
            
        except Exception as e:
            logger.error(f"Create note failed: {str(e)}")
            return None
    
    def update_item(self, item_id: str, **kwargs) -> bool:
        """Update an existing item.
        
        Args:
            item_id: Item ID to update
            **kwargs: Fields to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get current item
            current_item = self.get_item(item_id)
            if not current_item:
                return False
            
            # Update fields
            if 'name' in kwargs:
                current_item.name = kwargs['name']
            if 'username' in kwargs:
                current_item.username = kwargs['username']
            if 'password' in kwargs:
                current_item.password = kwargs['password']
            if 'uris' in kwargs:
                current_item.uris = kwargs['uris']
            if 'notes' in kwargs:
                current_item.notes = kwargs['notes']
            if 'folder_id' in kwargs:
                current_item.folder_id = kwargs['folder_id']
            
            # Convert back to JSON and update
            item_data = self._item_to_dict(current_item)
            result = self._run_bw_command(['edit', 'item', item_id], json.dumps(item_data))
            
            return result is not None
            
        except Exception as e:
            logger.error(f"Update item failed: {str(e)}")
            return False
    
    def delete_item(self, item_id: str) -> bool:
        """Delete an item.
        
        Args:
            item_id: Item ID to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self._run_bw_command(['delete', 'item', item_id])
            return True
        except Exception as e:
            logger.error(f"Delete item failed: {str(e)}")
            return False
    
    def list_folders(self) -> List[Dict[str, Any]]:
        """List all folders.
        
        Returns:
            List of folder dictionaries
        """
        try:
            # Ensure we're logged in first
            if not self._ensure_logged_in():
                logger.error("Not logged in, cannot list folders")
                return []
            
            cmd = ['list', 'folders']
            
            # Use pexpect for interactive password prompt
            logger.debug(f"Running bw command with pexpect: {' '.join(cmd)}")
            child = pexpect.spawn('env', ['NODE_TLS_REJECT_UNAUTHORIZED=0', 'bw'] + cmd, timeout=30)
            
            # Wait for password prompt and send password
            child.expect('Master password:')
            child.sendline(self.password)
            
            # Wait for completion and get output
            child.expect(pexpect.EOF)
            output = child.before.decode('utf-8')
            child.close()
            
            # Parse JSON output
            if output.strip():
                try:
                    folders_data = json.loads(output)
                    return folders_data.get('data', []) if isinstance(folders_data, dict) else folders_data
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse JSON output: {output}")
                    return []
            return []
            
        except pexpect.TIMEOUT:
            logger.error("List folders timed out")
            return []
        except Exception as e:
            logger.error(f"List folders failed: {str(e)}")
            return []
    
    def create_folder(self, name: str) -> Optional[str]:
        """Create a new folder.
        
        Args:
            name: Folder name
            
        Returns:
            Created folder ID or None if failed
        """
        try:
            folder_template = {"name": name}
            result = self._run_bw_command(['create', 'folder'], json.dumps(folder_template))
            
            if result and 'id' in result:
                return result['id']
            return None
        except Exception as e:
            logger.error(f"Create folder failed: {str(e)}")
            return None
    
    def _parse_item(self, item_data: Dict[str, Any]) -> Optional[BitwardenItem]:
        """Parse item data from bw CLI into BitwardenItem object.
        
        Args:
            item_data: Raw item data from bw CLI
            
        Returns:
            BitwardenItem object or None if parsing failed
        """
        try:
            item_id = item_data.get('id', '')
            name = item_data.get('name', '')
            item_type = item_data.get('type', 1)
            
            # Extract login data
            username = None
            password = None
            uris = []
            
            if item_type == 1 and 'login' in item_data:  # Login
                login_data = item_data['login']
                username = login_data.get('username')
                password = login_data.get('password')
                uris = [uri.get('uri', '') for uri in login_data.get('uris', [])]
            
            # Extract notes
            notes = item_data.get('notes', '')
            
            # Extract folder
            folder_id = item_data.get('folderId')
            
            # Extract favorite
            favorite = item_data.get('favorite', False)
            
            return BitwardenItem(
                id=item_id,
                name=name,
                username=username,
                password=password,
                uris=uris,
                notes=notes,
                folder_id=folder_id,
                type=item_type,
                favorite=favorite
            )
            
        except Exception as e:
            logger.error(f"Failed to parse item: {str(e)}")
            return None
    
    def _item_to_dict(self, item: BitwardenItem) -> Dict[str, Any]:
        """Convert BitwardenItem to dictionary for bw CLI.
        
        Args:
            item: BitwardenItem object
            
        Returns:
            Dictionary representation
        """
        item_dict = {
            "id": item.id,
            "name": item.name,
            "type": item.type,
            "notes": item.notes or "",
            "favorite": item.favorite
        }
        
        if item.folder_id:
            item_dict["folderId"] = item.folder_id
        
        if item.type == 1:  # Login
            item_dict["login"] = {
                "username": item.username or "",
                "password": item.password or "",
                "uris": [{"uri": uri} for uri in item.uris]
            }
        elif item.type == 2:  # SecureNote
            item_dict["secureNote"] = {"type": 0}
        
        return item_dict
