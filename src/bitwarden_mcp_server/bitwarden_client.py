"""
Bitwarden/Vaultwarden MCP Server Client

This module provides a client for interacting with Bitwarden/Vaultwarden
via the REST API for password management and secure notes.
"""

import requests
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

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
    organization_id: Optional[str] = None
    collection_ids: List[str] = None
    type: int = 1  # 1=Login, 2=SecureNote, 3=Card, 4=Identity
    favorite: bool = False
    reprompt: int = 0
    login: Optional[Dict] = None
    card: Optional[Dict] = None
    identity: Optional[Dict] = None
    secure_note: Optional[Dict] = None
    fields: List[Dict] = None
    password_history: List[Dict] = None
    revision_date: Optional[str] = None
    creation_date: Optional[str] = None
    deleted_date: Optional[str] = None

    def __post_init__(self):
        if self.uris is None:
            self.uris = []
        if self.collection_ids is None:
            self.collection_ids = []
        if self.fields is None:
            self.fields = []
        if self.password_history is None:
            self.password_history = []


class BitwardenClient:
    """Client for Bitwarden/Vaultwarden API operations."""
    
    def __init__(self, base_url: str, email: str, password: str, client_id: str = None, client_secret: str = None):
        """Initialize the Bitwarden client.
        
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
        self.client_id = client_id or "bitwarden-mcp-server"
        self.client_secret = client_secret or "bitwarden-mcp-secret"
        
        self.session = requests.Session()
        self.access_token = None
        self.refresh_token = None
        self.key = None
        
        # API endpoints
        self.auth_url = f"{self.base_url}/api/identity/connect/token"
        self.api_url = f"{self.base_url}/api"
        
    def _make_request(self, method: str, endpoint: str, data: Dict = None, headers: Dict = None) -> Dict[str, Any]:
        """Make an authenticated request to the Bitwarden API.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request data
            headers: Additional headers
            
        Returns:
            API response data
        """
        url = f"{self.api_url}{endpoint}"
        default_headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'bitwarden-mcp-server/1.0'
        }
        
        if self.access_token:
            default_headers['Authorization'] = f'Bearer {self.access_token}'
        
        if headers:
            default_headers.update(headers)
        
        try:
            logger.debug(f"Making {method} request to {url}")
            logger.debug(f"Headers: {default_headers}")
            if data:
                logger.debug(f"Data: {data}")
            
            response = self.session.request(
                method=method,
                url=url,
                headers=default_headers,
                json=data,
                timeout=30
            )
            
            logger.debug(f"Response status: {response.status_code}")
            logger.debug(f"Response headers: {dict(response.headers)}")
            logger.debug(f"Response body: {response.text[:500]}")
            
            response.raise_for_status()
            
            if response.content:
                return response.json()
            return {}
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            raise Exception(f"Bitwarden API request failed: {str(e)}")
    
    def authenticate(self) -> bool:
        """Authenticate with Bitwarden/Vaultwarden.
        
        Returns:
            True if authentication successful, False otherwise
        """
        try:
            auth_data = {
                'grant_type': 'password',
                'username': self.email,
                'password': self.password,
                'scope': 'api offline_access',
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
            
            logger.debug(f"Authenticating with {self.auth_url}")
            response = self.session.post(
                self.auth_url,
                data=auth_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=30
            )
            
            logger.debug(f"Auth response status: {response.status_code}")
            logger.debug(f"Auth response: {response.text[:500]}")
            
            response.raise_for_status()
            auth_result = response.json()
            
            self.access_token = auth_result.get('access_token')
            self.refresh_token = auth_result.get('refresh_token')
            self.key = auth_result.get('key')
            
            if not self.access_token:
                raise Exception("No access token received")
            
            logger.info("Successfully authenticated with Bitwarden")
            return True
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False
    
    def get_items(self, search: str = None, folder_id: str = None) -> List[BitwardenItem]:
        """Get all items from Bitwarden.
        
        Args:
            search: Search term to filter items
            folder_id: Filter by folder ID
            
        Returns:
            List of BitwardenItem objects
        """
        try:
            endpoint = "/ciphers"
            params = {}
            
            if search:
                params['search'] = search
            if folder_id:
                params['folderId'] = folder_id
            
            data = self._make_request('GET', endpoint, params)
            items = data.get('Data', {}).get('Ciphers', [])
            
            result = []
            for item_data in items:
                item = self._parse_item(item_data)
                if item:
                    result.append(item)
            
            logger.info(f"Retrieved {len(result)} items")
            return result
            
        except Exception as e:
            logger.error(f"Failed to get items: {str(e)}")
            return []
    
    def get_item(self, item_id: str) -> Optional[BitwardenItem]:
        """Get a specific item by ID.
        
        Args:
            item_id: Item ID
            
        Returns:
            BitwardenItem object or None if not found
        """
        try:
            endpoint = f"/ciphers/{item_id}"
            data = self._make_request('GET', endpoint)
            
            if data.get('Data'):
                return self._parse_item(data['Data'])
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get item {item_id}: {str(e)}")
            return None
    
    def create_item(self, name: str, item_type: int = 1, username: str = None, 
                   password: str = None, uris: List[str] = None, 
                   notes: str = None, folder_id: str = None) -> Optional[BitwardenItem]:
        """Create a new item.
        
        Args:
            name: Item name
            item_type: Item type (1=Login, 2=SecureNote, 3=Card, 4=Identity)
            username: Username (for login items)
            password: Password (for login items)
            uris: List of URIs (for login items)
            notes: Notes
            folder_id: Folder ID
            
        Returns:
            Created BitwardenItem object or None if failed
        """
        try:
            endpoint = "/ciphers"
            
            item_data = {
                'Type': item_type,
                'Name': name,
                'FolderId': folder_id,
                'Favorite': False,
                'Reprompt': 0,
                'OrganizationId': None,
                'CollectionIds': [],
                'Fields': [],
                'PasswordHistory': []
            }
            
            # Set type-specific data
            if item_type == 1:  # Login
                item_data['Login'] = {
                    'Uris': [{'Uri': uri, 'Match': 0} for uri in (uris or [])],
                    'Username': username,
                    'Password': password,
                    'Totp': None
                }
            elif item_type == 2:  # Secure Note
                item_data['SecureNote'] = {
                    'Type': 0
                }
                item_data['Notes'] = notes
            
            response_data = self._make_request('POST', endpoint, item_data)
            
            if response_data.get('Data'):
                return self._parse_item(response_data['Data'])
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to create item: {str(e)}")
            return None
    
    def update_item(self, item_id: str, name: str = None, username: str = None,
                   password: str = None, uris: List[str] = None, 
                   notes: str = None, folder_id: str = None) -> Optional[BitwardenItem]:
        """Update an existing item.
        
        Args:
            item_id: Item ID to update
            name: New name
            username: New username
            password: New password
            uris: New URIs
            notes: New notes
            folder_id: New folder ID
            
        Returns:
            Updated BitwardenItem object or None if failed
        """
        try:
            # First get the current item
            current_item = self.get_item(item_id)
            if not current_item:
                return None
            
            endpoint = f"/ciphers/{item_id}"
            
            # Prepare update data
            update_data = {
                'Id': item_id,
                'Type': current_item.type,
                'Name': name or current_item.name,
                'FolderId': folder_id or current_item.folder_id,
                'Favorite': current_item.favorite,
                'Reprompt': current_item.reprompt,
                'OrganizationId': current_item.organization_id,
                'CollectionIds': current_item.collection_ids,
                'Fields': current_item.fields,
                'PasswordHistory': current_item.password_history
            }
            
            # Update type-specific data
            if current_item.type == 1:  # Login
                login_data = current_item.login or {}
                if username is not None:
                    login_data['Username'] = username
                if password is not None:
                    login_data['Password'] = password
                if uris is not None:
                    login_data['Uris'] = [{'Uri': uri, 'Match': 0} for uri in uris]
                
                update_data['Login'] = login_data
            elif current_item.type == 2:  # Secure Note
                if notes is not None:
                    update_data['Notes'] = notes
                update_data['SecureNote'] = current_item.secure_note or {'Type': 0}
            
            response_data = self._make_request('PUT', endpoint, update_data)
            
            if response_data.get('Data'):
                return self._parse_item(response_data['Data'])
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to update item {item_id}: {str(e)}")
            return None
    
    def delete_item(self, item_id: str) -> bool:
        """Delete an item.
        
        Args:
            item_id: Item ID to delete
            
        Returns:
            True if deletion successful, False otherwise
        """
        try:
            endpoint = f"/ciphers/{item_id}"
            self._make_request('DELETE', endpoint)
            logger.info(f"Successfully deleted item {item_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete item {item_id}: {str(e)}")
            return False
    
    def get_folders(self) -> List[Dict[str, Any]]:
        """Get all folders.
        
        Returns:
            List of folder dictionaries
        """
        try:
            endpoint = "/folders"
            data = self._make_request('GET', endpoint)
            folders = data.get('Data', [])
            logger.info(f"Retrieved {len(folders)} folders")
            return folders
            
        except Exception as e:
            logger.error(f"Failed to get folders: {str(e)}")
            return []
    
    def create_folder(self, name: str) -> Optional[Dict[str, Any]]:
        """Create a new folder.
        
        Args:
            name: Folder name
            
        Returns:
            Created folder dictionary or None if failed
        """
        try:
            endpoint = "/folders"
            folder_data = {'Name': name}
            
            response_data = self._make_request('POST', endpoint, folder_data)
            
            if response_data.get('Data'):
                logger.info(f"Successfully created folder: {name}")
                return response_data['Data']
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to create folder {name}: {str(e)}")
            return None
    
    def _parse_item(self, item_data: Dict[str, Any]) -> Optional[BitwardenItem]:
        """Parse item data from API response.
        
        Args:
            item_data: Raw item data from API
            
        Returns:
            BitwardenItem object or None if parsing failed
        """
        try:
            return BitwardenItem(
                id=item_data.get('Id', ''),
                name=item_data.get('Name', ''),
                username=item_data.get('Login', {}).get('Username') if item_data.get('Login') else None,
                password=item_data.get('Login', {}).get('Password') if item_data.get('Login') else None,
                uris=[uri.get('Uri', '') for uri in item_data.get('Login', {}).get('Uris', [])] if item_data.get('Login') else [],
                notes=item_data.get('Notes'),
                folder_id=item_data.get('FolderId'),
                organization_id=item_data.get('OrganizationId'),
                collection_ids=item_data.get('CollectionIds', []),
                type=item_data.get('Type', 1),
                favorite=item_data.get('Favorite', False),
                reprompt=item_data.get('Reprompt', 0),
                login=item_data.get('Login'),
                card=item_data.get('Card'),
                identity=item_data.get('Identity'),
                secure_note=item_data.get('SecureNote'),
                fields=item_data.get('Fields', []),
                password_history=item_data.get('PasswordHistory', []),
                revision_date=item_data.get('RevisionDate'),
                creation_date=item_data.get('CreationDate'),
                deleted_date=item_data.get('DeletedDate')
            )
        except Exception as e:
            logger.error(f"Failed to parse item data: {str(e)}")
            return None
