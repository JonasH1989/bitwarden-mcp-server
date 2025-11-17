# Bitwarden MCP Server

An MCP (Model Context Protocol) server for interacting with Bitwarden/Vaultwarden for password and secure note management.

## Features

- **Password Management**: Create, update, delete, and search passwords
- **Secure Notes**: Manage secure notes and sensitive information
- **Folders**: Organize items in folders
- **Advanced Search**: Search items by name, type, folder
- **Secure Authentication**: Supports OAuth2 and password authentication

## Available Tools

### Search and Display
- `search_bitwarden_items`: Search items in Bitwarden
- `get_bitwarden_item`: Get details of a specific item
- `list_bitwarden_folders`: List all folders

### Creation
- `create_bitwarden_login`: Create a new login
- `create_bitwarden_note`: Create a new secure note
- `create_bitwarden_folder`: Create a new folder

### Update and Deletion
- `update_bitwarden_item`: Update an existing item
- `delete_bitwarden_item`: Delete an item

## Configuration

### Environment Variables

```bash
# Bitwarden Server
BITWARDEN_BASE_URL=https://vault.bitwarden.com  # or your Vaultwarden URL

# User credentials
BITWARDEN_EMAIL=your-email@example.com
BITWARDEN_PASSWORD=your-password

# API credentials (optional)
BITWARDEN_CLIENT_ID=bitwarden-mcp-server
BITWARDEN_CLIENT_SECRET=bitwarden-mcp-secret
```

## Installation

### Docker Compose

1. Copy the environment file and configure withu your credentials:
```bash
cp env.example .env
```

2. Build and run with Docker Compose:
```bash
docker compose up -d
```

