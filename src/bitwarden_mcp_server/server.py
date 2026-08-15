"""
Bitwarden MCP Server - Main server implementation - Docker/Environment version.
"""

import os
import logging
from typing import List, Dict, Any, Optional

from mcp.server.fastmcp import FastMCP

from .bw_client import BitwardenCLIClient, BitwardenItem

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastMCP
mcp = FastMCP("Bitwarden MCP Server")

# Default configuration
DEFAULT_BASE_URL = os.getenv("BITWARDEN_BASE_URL", "https://vault.bitwarden.com")
# User-API-Key (Format: "user.<uuid>") für bw login --apikey.
# Hinweis: Variable heißt BITWARDEN_CLIENT_ID (irreführender Name aus dem
# Original-Repo), aber inhaltlich ist es der User-API-Key, NICHT eine
# OAuth2-Client-ID. Service-User-Flow umgeht Master-Pwd komplett — der
# kaputte /identity/accounts/login Endpoint auf Vaultwarden ist irrelevant.
DEFAULT_API_KEY = os.getenv("BITWARDEN_CLIENT_ID", "")
# Legacy-Felder (deprecated — Master-Pwd-Flow nicht mehr benötigt):
DEFAULT_EMAIL = os.getenv("BITWARDEN_EMAIL", "")
DEFAULT_PASSWORD = os.getenv("BITWARDEN_PASSWORD", "")
DEFAULT_CLIENT_SECRET = os.getenv("BITWARDEN_CLIENT_SECRET", "")


def _handle_error(e: Exception, operation: str) -> str:
    """Handle errors and return formatted error message.
    
    Args:
        e: Exception object
        operation: Operation that failed
        
    Returns:
        Formatted error message
    """
    error_msg = str(e)
    logger.error(f"Error during {operation}: {error_msg}")
    return f"❌ Error during {operation}: {error_msg}"


def _get_client(base_url: str = None, api_key: str = None,
                email: str = None, password: str = None,
                client_secret: str = None) -> Optional[BitwardenCLIClient]:
    """Get authenticated Bitwarden client.
    
    Args:
        base_url: Bitwarden server URL
        api_key: User-API-Key (Format "user.<uuid>"). Bevorzugt für bw login --apikey.
        email: User email (deprecated — Legacy-Master-Pwd-Flow, nicht mehr benötigt)
        password: User password (deprecated — siehe oben)
        client_secret: Client secret (deprecated — Service-User-Credentials-Flow)
    
    Returns:
        Authenticated BitwardenClient or None if authentication failed
    """
    try:
        url = base_url or DEFAULT_BASE_URL
        key = api_key or DEFAULT_API_KEY
        # Legacy-Felder werden noch akzeptiert aber nicht mehr für Login benötigt.
        user_email = email or DEFAULT_EMAIL
        user_password = password or DEFAULT_PASSWORD
        csecret = client_secret or DEFAULT_CLIENT_SECRET

        if not key:
            logger.error("Missing API key (BITWARDEN_CLIENT_ID env var)")
            return None

        client = BitwardenCLIClient(url, api_key=key, email=user_email,
                                    password=user_password, client_secret=csecret)

        # First authenticate (login) — bw login --apikey, kein Master-Pwd nötig.
        if not client.authenticate():
            logger.error("Authentication failed")
            return None

        # KEIN unlock_vault() mehr nötig: bw login --apikey entschlüsselt
        # den Vault direkt (kein Master-Pwd, keine 2FA, kein /identity/accounts/login).

        return client
        
    except Exception as e:
        logger.error(f"Failed to create client: {str(e)}")
        return None


@mcp.tool()
def search_bitwarden_items(query: str = None, item_type: str = None,
                          folder_id: str = None, limit: int = 20,
                          base_url: str = None, api_key: str = None,
                          email: str = None, password: str = None,
                          client_secret: str = None) -> str:
    """Search Bitwarden items (passwords, notes, cards, identities).

    Args:
        query: Search term to filter items
        item_type: Filter by item type (login, note, card, identity)
        folder_id: Filter by folder ID
        limit: Maximum number of results (default: 20)
        base_url: Bitwarden server URL (defaults to BITWARDEN_BASE_URL env var)
        api_key: User-API-Key (defaults to BITWARDEN_CLIENT_ID env var — PREFERRED)
        email: User email (defaults to BITWARDEN_EMAIL env var — deprecated)
        password: User password (defaults to BITWARDEN_PASSWORD env var — deprecated)
        client_secret: Client secret (defaults to BITWARDEN_CLIENT_SECRET env var — deprecated)

    Returns:
        List of matching Bitwarden items
    """
    try:
        client = _get_client(base_url, api_key, email, password, client_secret)
        if not client:
            return "❌ Authentication failed. Please check credentials."
        
        items = client.search_items(query, folder_id)
        
        # Filter by type if specified
        if item_type:
            type_map = {
                'login': 1,
                'note': 2,
                'card': 3,
                'identity': 4
            }
            target_type = type_map.get(item_type.lower())
            if target_type:
                items = [item for item in items if item.type == target_type]
        
        # Limit results
        items = items[:limit]
        
        if not items:
            search_msg = f" matching '{query}'" if query else ""
            type_msg = f" of type '{item_type}'" if item_type else ""
            return f"🔍 No items found{search_msg}{type_msg}"
        
        result = f"🔍 **Bitwarden Items** (found {len(items)} items)\n\n"
        
        for i, item in enumerate(items, 1):
            type_names = {1: 'Login', 2: 'Secure Note', 3: 'Card', 4: 'Identity'}
            type_name = type_names.get(item.type, 'Unknown')
            
            result += f"### {i}. {item.name}\n"
            result += f"**Type:** {type_name}\n"
            result += f"**ID:** `{item.id}`\n"
            
            if item.username:
                result += f"**Username:** {item.username}\n"
            
            if item.uris:
                result += f"**URLs:** {', '.join(item.uris)}\n"
            
            if item.notes:
                notes_preview = item.notes[:100].replace('\n', ' ').strip()
                if len(item.notes) > 100:
                    notes_preview += "..."
                result += f"**Notes:** {notes_preview}\n"
            
            if item.folder_id:
                result += f"**Folder ID:** `{item.folder_id}`\n"
            
            if item.favorite:
                result += "**⭐ Favorite**\n"
            
            result += "\n"
        
        return result
        
    except Exception as e:
        return _handle_error(e, "searching items")


@mcp.tool()
def get_bitwarden_item(item_id: str, base_url: str = None, email: str = None,
                      password: str = None, api_key: str = None, 
                      client_secret: str = None) -> str:
    """Get detailed information about a specific Bitwarden item.
    
    Args:
        item_id: Item ID to retrieve
        base_url: Bitwarden server URL (defaults to BITWARDEN_BASE_URL env var)
        email: User email (defaults to BITWARDEN_EMAIL env var)
        password: User password (defaults to BITWARDEN_PASSWORD env var)
        api_key: User-API-Key (defaults to BITWARDEN_CLIENT_ID env var — PREFERRED)
        client_secret: Client secret (defaults to BITWARDEN_CLIENT_SECRET env var)
    
    Returns:
        Detailed item information
    """
    try:
        client = _get_client(base_url, api_key, email, password, client_secret)
        if not client:
            return "❌ Authentication failed. Please check credentials."
        
        item = client.get_item(item_id)
        if not item:
            return f"❌ Item not found: {item_id}"
        
        type_names = {1: 'Login', 2: 'Secure Note', 3: 'Card', 4: 'Identity'}
        type_name = type_names.get(item.type, 'Unknown')
        
        result = f"🔐 **{item.name}**\n\n"
        result += f"**Type:** {type_name}\n"
        result += f"**ID:** `{item.id}`\n"
        
        if item.username:
            result += f"**Username:** {item.username}\n"
        
        if item.password:
            result += f"**Password:** {'*' * len(item.password)}\n"
        
        if item.uris:
            result += f"**URLs:**\n"
            for uri in item.uris:
                result += f"  - {uri}\n"
        
        if item.notes:
            result += f"**Notes:**\n{item.notes}\n"
        
        if item.folder_id:
            result += f"**Folder ID:** `{item.folder_id}`\n"
        
        if item.organization_id:
            result += f"**Organization ID:** `{item.organization_id}`\n"
        
        if item.collection_ids:
            result += f"**Collection IDs:** {', '.join(item.collection_ids)}\n"
        
        if item.favorite:
            result += "**⭐ Favorite**\n"
        
        if item.creation_date:
            result += f"**Created:** {item.creation_date}\n"
        
        if item.revision_date:
            result += f"**Updated:** {item.revision_date}\n"
        
        return result
        
    except Exception as e:
        return _handle_error(e, "getting item")


@mcp.tool()
def create_bitwarden_login(name: str, username: str, password: str, 
                          uris: List[str] = None, notes: str = None,
                          folder_id: str = None, base_url: str = None,
                          email: str = None, password_param: str = None,
                          api_key: str = None, client_secret: str = None) -> str:
    """Create a new login item in Bitwarden.
    
    Args:
        name: Item name
        username: Username
        password: Password
        uris: List of URLs (optional)
        notes: Notes (optional)
        folder_id: Folder ID (optional)
        base_url: Bitwarden server URL (defaults to BITWARDEN_BASE_URL env var)
        email: User email (defaults to BITWARDEN_EMAIL env var)
        password_param: User password (defaults to BITWARDEN_PASSWORD env var)
        api_key: User-API-Key (defaults to BITWARDEN_CLIENT_ID env var — PREFERRED)
        client_secret: Client secret (defaults to BITWARDEN_CLIENT_SECRET env var)
    
    Returns:
        Creation result message
    """
    try:
        client = _get_client(base_url, api_key, email, password_param, client_secret)
        if not client:
            return "❌ Authentication failed. Please check credentials."
        
        item = client.create_login(
            name=name,
            username=username,
            password=password,
            uris=uris or [],
            notes=notes,
            folder_id=folder_id
        )
        
        if item:
            return f"✅ Successfully created login item: {item.name} (ID: {item.id})"
        else:
            return "❌ Failed to create login item"
        
    except Exception as e:
        return _handle_error(e, "creating login item")


@mcp.tool()
def create_bitwarden_note(name: str, content: str, folder_id: str = None,
                         base_url: str = None, email: str = None,
                         password: str = None, api_key: str = None,
                         client_secret: str = None) -> str:
    """Create a new secure note in Bitwarden.
    
    Args:
        name: Note name
        content: Note content
        folder_id: Folder ID (optional)
        base_url: Bitwarden server URL (defaults to BITWARDEN_BASE_URL env var)
        email: User email (defaults to BITWARDEN_EMAIL env var)
        password: User password (defaults to BITWARDEN_PASSWORD env var)
        api_key: User-API-Key (defaults to BITWARDEN_CLIENT_ID env var — PREFERRED)
        client_secret: Client secret (defaults to BITWARDEN_CLIENT_SECRET env var)
    
    Returns:
        Creation result message
    """
    try:
        client = _get_client(base_url, api_key, email, password, client_secret)
        if not client:
            return "❌ Authentication failed. Please check credentials."
        
        item = client.create_note(
            name=name,
            content=content,
            folder_id=folder_id
        )
        
        if item:
            return f"✅ Successfully created secure note: {item.name} (ID: {item.id})"
        else:
            return "❌ Failed to create secure note"
        
    except Exception as e:
        return _handle_error(e, "creating secure note")


@mcp.tool()
def update_bitwarden_item(item_id: str, name: str = None, username: str = None,
                         password: str = None, uris: List[str] = None,
                         notes: str = None, folder_id: str = None,
                         base_url: str = None, email: str = None,
                         password_param: str = None, api_key: str = None,
                         client_secret: str = None) -> str:
    """Update an existing Bitwarden item.
    
    Args:
        item_id: Item ID to update
        name: New name (optional)
        username: New username (optional)
        password: New password (optional)
        uris: New URLs (optional)
        notes: New notes (optional)
        folder_id: New folder ID (optional)
        base_url: Bitwarden server URL (defaults to BITWARDEN_BASE_URL env var)
        email: User email (defaults to BITWARDEN_EMAIL env var)
        password_param: User password (defaults to BITWARDEN_PASSWORD env var)
        api_key: User-API-Key (defaults to BITWARDEN_CLIENT_ID env var — PREFERRED)
        client_secret: Client secret (defaults to BITWARDEN_CLIENT_SECRET env var)
    
    Returns:
        Update result message
    """
    try:
        client = _get_client(base_url, api_key, email, password_param, client_secret)
        if not client:
            return "❌ Authentication failed. Please check credentials."
        
        item = client.update_item(
            item_id=item_id,
            name=name,
            username=username,
            password=password,
            uris=uris,
            notes=notes,
            folder_id=folder_id
        )
        
        if item:
            return f"✅ Successfully updated item: {item.name} (ID: {item.id})"
        else:
            return f"❌ Failed to update item: {item_id}"
        
    except Exception as e:
        return _handle_error(e, "updating item")


@mcp.tool()
def delete_bitwarden_item(item_id: str, base_url: str = None, email: str = None,
                         password: str = None, api_key: str = None,
                         client_secret: str = None) -> str:
    """Delete a Bitwarden item.
    
    Args:
        item_id: Item ID to delete
        base_url: Bitwarden server URL (defaults to BITWARDEN_BASE_URL env var)
        email: User email (defaults to BITWARDEN_EMAIL env var)
        password: User password (defaults to BITWARDEN_PASSWORD env var)
        api_key: User-API-Key (defaults to BITWARDEN_CLIENT_ID env var — PREFERRED)
        client_secret: Client secret (defaults to BITWARDEN_CLIENT_SECRET env var)
    
    Returns:
        Deletion result message
    """
    try:
        client = _get_client(base_url, api_key, email, password, client_secret)
        if not client:
            return "❌ Authentication failed. Please check credentials."
        
        success = client.delete_item(item_id)
        
        if success:
            return f"✅ Successfully deleted item: {item_id}"
        else:
            return f"❌ Failed to delete item: {item_id}"
        
    except Exception as e:
        return _handle_error(e, "deleting item")


@mcp.tool()
def list_bitwarden_folders(base_url: str = None, email: str = None,
                          password: str = None, api_key: str = None,
                          client_secret: str = None) -> str:
    """List all Bitwarden folders.
    
    Args:
        base_url: Bitwarden server URL (defaults to BITWARDEN_BASE_URL env var)
        email: User email (defaults to BITWARDEN_EMAIL env var)
        password: User password (defaults to BITWARDEN_PASSWORD env var)
        api_key: User-API-Key (defaults to BITWARDEN_CLIENT_ID env var — PREFERRED)
        client_secret: Client secret (defaults to BITWARDEN_CLIENT_SECRET env var)
    
    Returns:
        List of folders
    """
    try:
        client = _get_client(base_url, api_key, email, password, client_secret)
        if not client:
            return "❌ Authentication failed. Please check credentials."
        
        folders = client.list_folders()
        
        if not folders:
            return "📁 No folders found"
        
        result = f"📁 **Bitwarden Folders** (found {len(folders)} folders)\n\n"
        
        for i, folder in enumerate(folders, 1):
            result += f"### {i}. {folder.get('Name', 'Unknown')}\n"
            result += f"**ID:** `{folder.get('Id', 'Unknown')}`\n"
            result += f"**Revision Date:** {folder.get('RevisionDate', 'Unknown')}\n"
            result += "\n"
        
        return result
        
    except Exception as e:
        return _handle_error(e, "listing folders")


@mcp.tool()
def create_bitwarden_folder(name: str, base_url: str = None, email: str = None,
                           password: str = None, api_key: str = None,
                           client_secret: str = None) -> str:
    """Create a new Bitwarden folder.
    
    Args:
        name: Folder name
        base_url: Bitwarden server URL (defaults to BITWARDEN_BASE_URL env var)
        email: User email (defaults to BITWARDEN_EMAIL env var)
        password: User password (defaults to BITWARDEN_PASSWORD env var)
        api_key: User-API-Key (defaults to BITWARDEN_CLIENT_ID env var — PREFERRED)
        client_secret: Client secret (defaults to BITWARDEN_CLIENT_SECRET env var)
    
    Returns:
        Creation result message
    """
    try:
        client = _get_client(base_url, api_key, email, password, client_secret)
        if not client:
            return "❌ Authentication failed. Please check credentials."
        
        folder = client.create_folder(name)
        
        if folder:
            return f"✅ Successfully created folder: {name} (ID: {folder.get('Id', 'Unknown')})"
        else:
            return f"❌ Failed to create folder: {name}"
        
    except Exception as e:
        return _handle_error(e, "creating folder")


def main() -> None:
    """Main entry point for the MCP server."""
    import os
    from dotenv import load_dotenv
    
    # Load environment variables
    load_dotenv()
    
    # Fix Pydantic `lifespan` forward-reference (sonst Settings-Auflösung kaputt)
    try:
        from mcp.server.fastmcp.settings import Settings
        Settings.model_rebuild()
    except Exception:
        pass
    
    # Configure FastMCP settings for streamable HTTP transport
    mcp.settings.host = os.getenv("SERVER_HOST", "0.0.0.0")
    mcp.settings.port = int(os.getenv("SERVER_PORT", "8007"))
    mcp.settings.stateless_http = True  # Enable stateless mode
    
    # Erstelle die ASGI-App
    app = mcp.streamable_http_app()
    
    # Health-Check-Endpoint hinzufügen (GET /health → 200 OK).
    # Wird von Coolify als Health-Check-Pfad genutzt.
    from starlette.responses import JSONResponse
    async def health_endpoint(request):
        """Health-Check-Endpoint für Coolify/Monitoring."""
        return JSONResponse({
            "status": "healthy",
            "server": "Bitwarden MCP Server",
            "version": "1.29.0"
        })
    app.add_route("/health", health_endpoint, methods=["GET"])
    logger.info("Health-Check-Endpoint registriert: GET /health")
    
    # Fix: TrustedHostMiddleware lehnt alle Hosts ab → 421. Umgehe das,
    # indem ich den Host-Header im ASGI-Scope auf "localhost" setze
    # BEVOR irgendeine Middleware ihn sieht. Das ist robuster als
    # user_middleware zu manipulieren (was in v3 nicht funktioniert hat).
    class HostOverrideASGI:
        """Override den Host-Header im ASGI-Scope auf 'localhost'."""
        def __init__(self, inner_app):
            self.inner_app = inner_app
        async def __call__(self, scope, receive, send):
            if scope["type"] in ("http", "websocket") and "headers" in scope:
                new_headers = []
                for name, value in scope["headers"]:
                    if name == b"host":
                        # Ersetze Host mit "localhost:PORT" (was die Middleware erlaubt)
                        value = f"localhost:{mcp.settings.port}".encode()
                    new_headers.append((name, value))
                scope["headers"] = new_headers
            await self.inner_app(scope, receive, send)
    
    # Wrap die App
    wrapped_app = HostOverrideASGI(app)
    
    # Run with uvicorn directly
    import uvicorn
    uvicorn.run(wrapped_app, host=mcp.settings.host, port=mcp.settings.port)


# Export the Starlette/FastAPI app for testing and external use
app = mcp.streamable_http_app()


if __name__ == "__main__":
    main()
