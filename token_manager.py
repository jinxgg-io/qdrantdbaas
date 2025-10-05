#!/usr/bin/env python3
import jwt
import uuid
import json
import secrets
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from pathlib import Path
from qdrant_client import QdrantClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QdrantAuthManager:
    _token_length = 32
    def __init__(self, api_key: Optional[str] = None,
                 read_only_api_key: Optional[str] = None,
                 config_path: str = "qdrant_auth_config.json"):
        self.config_path = config_path
        self.api_key = api_key or secrets.token_urlsafe(QdrantAuthManager._token_length)
        self.read_only_api_key = read_only_api_key or secrets.token_urlsafe(QdrantAuthManager._token_length)
        self.algorithm = "HS256"  # Qdrant uses HS256 for JWT
        self.config = self._load_or_create_config()
    
    def _load_or_create_config(self) -> Dict:
        config_file = Path(self.config_path)
        
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                logger.info(f"Loaded token configuration from {self.config_path}")
                return config
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        # Create default configuration
        config = {
            "api_key": self.api_key,
            "read_only_api_key": self.read_only_api_key,
            "jwt_rbac_enabled": True,
            "default_expiry_hours": 24,
            "max_expiry_hours": 168,  # 7 days
            "access_levels": {
                "read": "r",      # Read-only access
                "write": "rw",    # Read-write access  
                "manage": "m"     # Full management access
            },
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        self._save_config(config)
        return config
    
    def _save_config(self, config: Dict):
        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2, default=str)
            logger.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    def generate_jwt_token(self, 
                          user_id: str,
                          access_level: str = "read", # read, write, manage
                          expiry_hours: Optional[int] = None,
                          collections: Optional[List[Dict]] = None,
                          value_exists_validation: Optional[Dict] = None) -> Dict:
        if access_level not in self.config["access_levels"]:
            raise ValueError(f"Invalid access level: {access_level}. Must be one of {list(self.config['access_levels'].keys())}")
        
        # Set expiry
        expiry_hours = expiry_hours or self.config["default_expiry_hours"]
        if expiry_hours > self.config["max_expiry_hours"]:
            raise ValueError(f"Expiry hours cannot exceed {self.config['max_expiry_hours']}")
        
        # Generate token ID and timestamps
        jwt_token_id = str(uuid.uuid4())
        issued_at = datetime.now()
        expires_at = issued_at + timedelta(hours=expiry_hours)

        jwt_payload = dict(exp=int(expires_at.timestamp()))
        
        # Add access control
        if access_level == "read":
            jwt_payload["access"] = "r"
        elif access_level == "write":
            if collections:
                jwt_payload["access"] = collections
            else:
                jwt_payload["access"] = "rw"  # Global read-write if no collections specified
        elif access_level == "manage":
            # Manage access is default if no access claim is present
            pass

        if collections and access_level != "manage":
            payload["access"] = collections

        if value_exists_validation:
            jwt_payload["value_exists"] = value_exists_validation

        token = jwt.encode(jwt_payload, self.api_key, algorithm=self.algorithm)
        
        result_token = {
            "token": token,
            "token_id": jwt_token_id,
            "user_id": user_id,
            "access_level": access_level,
            "collections": collections,
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "expires_in_seconds": int((expires_at - issued_at).total_seconds()),
            "token_type": "qdrant_jwt"
        }
        
        logger.info(f"Generated Qdrant JWT token for user {user_id} with access level {access_level}")
        return result_token
    
    def validate_jwt_token(self, token: str) -> Dict:
        try:
            jwt_payload = jwt.decode(token, self.api_key, algorithms=[self.algorithm])
            logger.debug(f"Qdrant JWT token validated successfully")
            return jwt_payload
        except jwt.ExpiredSignatureError:
            logger.warning("Qdrant JWT token has expired")
            raise
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid Qdrant JWT token: {e}")
            raise
    
    def get_qdrant_client(self, 
                         qdrant_url: str = "http://localhost:6333", 
                         api_key_type: str = "master") -> QdrantClient:
        if api_key_type == "master":
            api_key = self.api_key
        elif api_key_type == "readonly":
            api_key = self.read_only_api_key
        else:
            raise ValueError(f"Invalid API key type: {api_key_type}")
        
        try:
            client = QdrantClient(
                url=qdrant_url,
                api_key=api_key
            )
            logger.info(f"Created Qdrant client with {api_key_type} API key")
            return client
        except Exception as e:
            logger.error(f"Failed to create Qdrant client: {e}")
            raise e
    
    def test_qdrant_connection(self, qdrant_url: str = "http://localhost:6333") -> Dict:
        results = {
            "qdrant_url": qdrant_url,
            "master_key_valid": False,
            "readonly_key_valid": False,
            "version": None,
            "error": None
        }
        
        try:
            # Test master API key
            client = QdrantClient(url=qdrant_url, api_key=self.api_key)
            results["master_key_valid"] = True
            results["version"] = client.info().version
            logger.info("Master API key connection successful")
            
            # Test read-only API key
            try:
                readonly_client = QdrantClient(url=qdrant_url, api_key=self.read_only_api_key)
                readonly_client.get_collections()
                results["readonly_key_valid"] = True
                logger.info("Read-only API key connection successful")
            except Exception as cliex:
                logger.warning(f"Read-only API key test failed: {cliex}")
        except Exception as e:
            results["error"] = str(e)
            logger.error(f"Qdrant connection test failed: {e}")
        
        return results
    
    def generate_presigned_url(self, 
                              base_url: str,
                              endpoint: str = "",
                              method: str = "GET",
                              user_id: str = "anonymous",
                              access_level: str = "read",
                              expiry_hours: int = 1,
                              collections: Optional[List[Dict]] = None) -> Dict:
        # Generate Qdrant JWT token
        token_info = self.generate_jwt_token(
            user_id=user_id,
            access_level=access_level,
            expiry_hours=expiry_hours,
            collections=collections
        )
        
        # Build URL with JWT token as api-key parameter
        separator = "&" if "?" in base_url else "?"
        presigned_url = f"{base_url.rstrip('/')}{endpoint}{separator}api-key={token_info['token']}"
        
        url_result = {
            "url": presigned_url,
            "method": method,
            "jwt_token": token_info["token"],
            "expires_at": token_info["expires_at"],
            "expires_in_seconds": token_info["expires_in_seconds"],
            "access_level": access_level,
            "collections": collections,
            "user_id": user_id,
            "usage_instructions": {
                "curl": f"curl -X {method} '{presigned_url}'",
                "header_auth": f"Authorization: Bearer {token_info['token']}",
                "api_key_header": f"Api-Key: {token_info['token']}"
            }
        }
        
        logger.info(f"Generated pre-signed URL for {method} {endpoint} (user: {user_id}, access: {access_level})")
        return url_result
    
    def create_api_key(self, 
                      name: str,
                      user_id: str,
                      access_level: str = "read",
                      collections: Optional[List[str]] = None,
                      long_lived: bool = False) -> Dict:
        expiry_hours = 8760 if long_lived else None  # 1 year or default
        
        token_info = self.generate_jwt_token(
            user_id=user_id,
            access_level=access_level,
            expiry_hours=expiry_hours,
            collections=collections
        )
        
        # Generate a more user-friendly key format
        key_prefix = "qdr"
        key_hash = hashlib.sha256(token_info["token"].encode()).hexdigest()[:16]
        api_key = f"{key_prefix}_{key_hash}"
        
        api_result = {
            "api_key": api_key,
            "name": name,
            "token": token_info["token"],
            "user_id": user_id,
            "access_level": access_level,
            "collections": collections,
            "created_at": token_info["issued_at"],
            "expires_at": token_info["expires_at"],
            "long_lived": long_lived
        }
        
        # Save API key info
        self._save_api_key(api_key, api_result)
        
        logger.info(f"Created API key '{name}' for user {user_id}")
        return api_result
    
    @staticmethod
    def _save_api_key(api_key: str, key_info: Dict):
        """Save API key information"""
        keys_file = Path("api_keys.json")
        
        try:
            if keys_file.exists():
                with open(keys_file, 'r') as f:
                    keys_data = json.load(f)
            else:
                keys_data = {}
            
            keys_data[api_key] = key_info
            
            with open(keys_file, 'w') as f:
                json.dump(keys_data, f, indent=2, default=str)
                
        except Exception as e:
            logger.error(f"Error saving API key: {e}")
    
    @staticmethod
    def revoke_token(token_id: str) -> bool:
        revoked_file = Path("revoked_tokens.json")
        
        try:
            if revoked_file.exists():
                with open(revoked_file, 'r') as f:
                    revoked = json.load(f)
            else:
                revoked = []
            
            if token_id not in revoked:
                revoked.append(token_id)
                
                with open(revoked_file, 'w') as f:
                    json.dump(revoked, f, indent=2)
                
                logger.info(f"Revoked token: {token_id}")
                return True
        except Exception as e:
            logger.error(f"Error revoking token: {e}")
        
        return False
    
    @staticmethod
    def is_token_revoked(token_id: str) -> bool:
        """Check if a token is revoked"""
        revoked_file = Path("revoked_tokens.json")
        
        try:
            if revoked_file.exists():
                with open(revoked_file, 'r') as f:
                    revoked = json.load(f)
                return token_id in revoked
        except Exception as e:
            logger.error(f"Error checking revoked tokens: {e}")
        
        return False
    
    @staticmethod
    def list_tokens() -> List[Dict]:
        """List all API keys (for management purposes)"""
        keys_file = Path("api_keys.json")
        
        try:
            if keys_file.exists():
                with open(keys_file, 'r') as f:
                    keys_data = json.load(f)
                
                # Return list without actual tokens for security
                return [
                    {
                        "api_key": key,
                        "name": info.get("name"),
                        "user_id": info.get("user_id"),
                        "permissions": info.get("permissions"),
                        "created_at": info.get("created_at"),
                        "expires_at": info.get("expires_at"),
                        "long_lived": info.get("long_lived", False)
                    }
                    for key, info in keys_data.items()
                ]
        except Exception as e:
            logger.error(f"Error listing tokens: {e}")
        
        return []



if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Qdrant Token Manager CLI")
    parser.add_argument("action", choices=["generate", "validate", "presign", "apikey", "list", "revoke"])
    parser.add_argument("--user-id", default="test-user", help="User ID")
    parser.add_argument("--permissions", nargs="+", default=["read"], help="Permissions")
    parser.add_argument("--expiry", type=int, default=24, help="Expiry in hours")
    parser.add_argument("--url", help="Base URL for pre-signed URLs")
    parser.add_argument("--endpoint", default="", help="API endpoint")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--token", help="Token to validate")
    parser.add_argument("--name", help="API key name")
    parser.add_argument("--long-lived", action="store_true", help="Create long-lived API key")
    
    args = parser.parse_args()
    
    manager = QdrantAuthManager()
    # Convert permissions list to access level
    if "manage" in args.permissions:
        access_level = "manage"
    elif "write" in args.permissions:
        access_level = "write"
    else:
        access_level = "read"

    if args.action == "generate":
        result = manager.generate_jwt_token(
            user_id=args.user_id,
            access_level=access_level,
            expiry_hours=args.expiry
        )
        print(json.dumps(result, indent=2))
    elif args.action == "validate":
        if not args.token:
            print("Error: --token required for validation")
            exit(1)
        
        try:
            payload = manager.validate_jwt_token(args.token)
            print(json.dumps(payload, indent=2, default=str))
        except Exception as e:
            print(f"Error: {e}")
            exit(1)
    elif args.action == "presign":
        if not args.url:
            print("Error: --url required for pre-signed URLs")
            exit(1)
        
        result = manager.generate_presigned_url(
            base_url=args.url,
            endpoint=args.endpoint,
            method=args.method,
            user_id=args.user_id,
            access_level=access_level,
            expiry_hours=args.expiry
        )
        print(json.dumps(result, indent=2))
    elif args.action == "apikey":
        if not args.name:
            print("Error: --name required for API keys")
            exit(1)
        
        result = manager.create_api_key(
            name=args.name,
            user_id=args.user_id,
            access_level=access_level,
            long_lived=args.long_lived
        )
        print(json.dumps(result, indent=2))
    elif args.action == "list":
        tokens = manager.list_tokens()
        print(json.dumps(tokens, indent=2))
    elif args.action == "revoke":
        if not args.token:
            print("Error: --token required for revocation")
            exit(1)
        
        try:
            payload = manager.validate_jwt_token(args.token)
            token_id = payload.get("jti")
            if manager.revoke_token(token_id):
                print(f"Token {token_id} revoked successfully")
            else:
                print("Failed to revoke token")
        except Exception as e:
            print(f"Error: {e}")
            exit(1)
