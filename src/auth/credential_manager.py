"""
Secure credential management for the expense tracker.
Handles authentication tokens and sensitive credentials securely.
"""

import os
import json
from pathlib import Path
from typing import Optional, Dict
from cryptography.fernet import Fernet
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from loguru import logger

class CredentialManager:
    """Manages secure storage and retrieval of credentials."""
    
    def __init__(self, config_dir: str = None):
        self.config_dir = Path(config_dir) if config_dir else Path.home() / '.expense-tracker'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self._init_encryption()
    
    def _init_encryption(self):
        """Initialize or load encryption key."""
        key_file = self.config_dir / 'encryption.key'
        if key_file.exists():
            self.key = key_file.read_bytes()
        else:
            self.key = Fernet.generate_key()
            key_file.write_bytes(self.key)
            key_file.chmod(0o600)  # Restrict permissions
        
        self.cipher = Fernet(self.key)
    
    def get_google_credentials(self) -> Credentials:
        """Get or refresh Google API credentials."""
        creds = None
        token_path = self.config_dir / 'token.encrypted'
        
        if token_path.exists():
            try:
                encrypted_token = token_path.read_bytes()
                token_data = json.loads(self.cipher.decrypt(encrypted_token))
                creds = Credentials.from_authorized_user_info(token_data)
            except Exception as e:
                logger.warning(f"Error loading stored credentials: {e}")
        
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except Exception as e:
                    logger.error(f"Error refreshing credentials: {e}")
                    creds = None
            
            if not creds:
                creds = self._handle_oauth_flow()
            
            # Save the refreshed/new credentials
            self._save_credentials(creds)
        
        return creds
    
    def _handle_oauth_flow(self) -> Credentials:
        """Handle OAuth2 flow for new credentials."""
        creds_file = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
        if not creds_file or not os.path.exists(creds_file):
            raise ValueError("Google credentials file not found!")
            
        flow = InstalledAppFlow.from_client_secrets_file(
            creds_file,
            [
                'https://www.googleapis.com/auth/gmail.readonly',
                'https://www.googleapis.com/auth/drive.file',
                'https://www.googleapis.com/auth/spreadsheets'
            ]
        )
        
        return flow.run_local_server(port=0)
    
    def _save_credentials(self, creds: Credentials):
        """Securely save credentials."""
        token_data = json.dumps(self._credentials_to_dict(creds))
        encrypted_token = self.cipher.encrypt(token_data.encode())
        token_path = self.config_dir / 'token.encrypted'
        token_path.write_bytes(encrypted_token)
        token_path.chmod(0o600)
    
    @staticmethod
    def _credentials_to_dict(creds: Credentials) -> Dict:
        """Convert credentials to dictionary format."""
        return {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes
        }
    
    def get_email_credentials(self) -> Dict[str, str]:
        """Get email credentials from environment."""
        email = os.getenv('PRIMARY_EMAIL')
        password = os.getenv('EMAIL_APP_PASSWORD')
        
        if not email or not password:
            raise ValueError("Email credentials not found in environment variables!")
        
        return {
            'email': email,
            'password': password
        }
    
    def clear_stored_credentials(self):
        """Clear all stored credentials."""
        token_path = self.config_dir / 'token.encrypted'
        if token_path.exists():
            token_path.unlink()
        logger.info("Cleared stored credentials")