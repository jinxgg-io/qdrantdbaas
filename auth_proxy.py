#!/usr/bin/env python3
import os
import json
import httpx
import asyncio
import logging
from typing import Dict, Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from token_manager import QdrantAuthManager
import jwt

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QdrantAuthProxy:
    def __init__(self, qdrant_host: str = "localhost", qdrant_port: int = 6333):
        self.qdrant_host = qdrant_host
        self.qdrant_port = qdrant_port
        self.qdrant_url = f"http://{qdrant_host}:{qdrant_port}"
        self.token_manager = QdrantAuthManager()
        
        # FastAPI app
        self.app = FastAPI(
            title="Qdrant DBaaS Authentication Proxy",
            description="JWT-authenticated proxy for Qdrant vector database",
            version="1.0.0"
        )
        
        # Enable CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Setup routes
        self._setup_routes()
        
    def _setup_routes(self):
        """Setup FastAPI routes"""
        
        @self.app.middleware("http")
        async def log_requests(request: Request, call_next):
            """Log all requests"""
            start_time = asyncio.get_event_loop().time()
            
            # Get client IP
            client_ip = request.client.host
            if "x-forwarded-for" in request.headers:
                client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()
            
            logger.info(f"{request.method} {request.url.path} - Client: {client_ip}")
            
            response = await call_next(request)
            
            process_time = asyncio.get_event_loop().time() - start_time
            logger.info(f"Completed in {process_time:.3f}s - Status: {response.status_code}")
            
            return response
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint"""
            try:
                # Check Qdrant connection
                async with httpx.AsyncClient() as client:
                    response = await client.get(f"{self.qdrant_url}/", timeout=5.0)
                    qdrant_status = "healthy" if response.status_code == 200 else "unhealthy"
            except Exception as e:
                qdrant_status = f"error: {str(e)}"
            
            return {
                "status": "healthy",
                "proxy_version": "1.0.0",
                "qdrant_backend": qdrant_status,
                "authentication": "enabled"
            }
        
        @self.app.post("/auth/token")
        async def generate_token(request: Request):
            """Generate a new JWT token"""
            try:
                body = await request.json()
                
                user_id = body.get("user_id", "anonymous")
                permissions = body.get("permissions", "read")
                expiry_hours = body.get("expiry_hours", 24)
                collections = body.get("collections")
                
                token_info = self.token_manager.generate_jwt_token(
                    user_id=user_id,
                    access_level=permissions,
                    expiry_hours=expiry_hours,
                    collections=collections
                )
                return token_info
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                logger.error(f"Error generating token: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.post("/auth/presigned-url")
        async def generate_presigned_url(request: Request):
            """Generate pre-signed URL for specific endpoint"""
            try:
                body = await request.json()
                
                endpoint = body.get("endpoint", "")
                method = body.get("method", "GET")
                user_id = body.get("user_id", "anonymous")
                permissions = body.get("permissions", "read")
                expiry_hours = body.get("expiry_hours", 1)
                
                # Get base URL from request
                base_url = str(request.base_url).rstrip('/')
                
                presigned_info = self.token_manager.generate_presigned_url(
                    base_url=base_url,
                    endpoint=endpoint,
                    method=method,
                    user_id=user_id,
                    access_level=permissions,
                    expiry_hours=expiry_hours
                )
                
                return presigned_info
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                logger.error(f"Error generating pre-signed URL: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.post("/auth/api-key")
        async def create_api_key(request: Request):
            """Create a new API key"""
            try:
                body = await request.json()
                
                name = body.get("name")
                if not name:
                    raise ValueError("API key name is required")
                
                user_id = body.get("user_id", "anonymous")
                permissions = body.get("permissions", "read")
                collections = body.get("collections")
                long_lived = body.get("long_lived", False)
                
                api_key_info = self.token_manager.create_api_key(
                    name=name,
                    user_id=user_id,
                    access_level=permissions,
                    collections=collections,
                    long_lived=long_lived
                )
                
                return api_key_info
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            except Exception as e:
                logger.error(f"Error creating API key: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.get("/auth/tokens")
        async def list_tokens():
            """List all API keys"""
            try:
                tokens = self.token_manager.list_tokens()
                return {"tokens": tokens}
            except Exception as e:
                logger.error(f"Error listing tokens: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.delete("/auth/token/{token_id}")
        async def revoke_token(token_id: str):
            """Revoke a token"""
            try:
                success = self.token_manager.revoke_token(token_id)
                if success:
                    return {"message": f"Token {token_id} revoked successfully"}
                else:
                    raise HTTPException(status_code=404, detail="Token not found")
            except Exception as e:
                logger.error(f"Error revoking token: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        # Proxy all other requests to Qdrant with authentication
        @self.app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
        async def proxy_to_qdrant(request: Request, path: str = ""):
            """Proxy authenticated requests to Qdrant"""
            return await self._proxy_request(request, path)
    
    async def _get_token_from_request(self, request: Request) -> Optional[str]:
        """Extract JWT token from request"""
        # Try Authorization header first
        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return auth_header.split(" ", 1)[1]
        
        # Try query parameter
        token = request.query_params.get("token")
        if token:
            return token
        
        # Try API key header
        api_key = request.headers.get("x-api-key")
        if api_key:
            # Look up API key and get associated token
            return await self._get_token_from_api_key(api_key)
        
        return None
    
    @staticmethod
    async def _get_token_from_api_key(api_key: str) -> Optional[str]:
        """Get JWT token from API key"""
        try:
            keys_data = {}
            keys_file = "api_keys.json"
            
            if os.path.exists(keys_file):
                with open(keys_file, 'r') as f:
                    keys_data = json.load(f)
            
            key_info = keys_data.get(api_key)
            if key_info:
                return key_info.get("token")
        except Exception as e:
            logger.error(f"Error looking up API key: {e}")
        
        return None
    
    @staticmethod
    def _validate_permissions(token_payload: Dict, request: Request) -> bool:
        """Validate if token has required permissions for the request"""
        method = request.method.upper()
        path = request.url.path
        
        permissions = token_payload.get("permissions", [])
        
        # Define permission requirements based on HTTP method and path
        if method in ["GET", "HEAD", "OPTIONS"]:
            required_permission = "read"
        elif method in ["POST", "PUT", "PATCH", "DELETE"]:
            if path.startswith("/collections") and method == "POST":
                required_permission = "write"
            elif method == "DELETE":
                required_permission = "admin"
            else:
                required_permission = "write"
        else:
            required_permission = "admin"
        
        # Check if user has required permission
        if required_permission not in permissions and "admin" not in permissions:
            return False
        
        # Check collection restrictions
        allowed_collections = token_payload.get("collections", [])
        if allowed_collections:  # If collections are restricted
            # Extract collection name from path
            path_parts = path.strip("/").split("/")
            if len(path_parts) >= 2 and path_parts[0] == "collections":
                collection_name = path_parts[1]
                if collection_name not in allowed_collections:
                    return False
        
        return True
    
    async def _proxy_request(self, request: Request, path: str) -> Response:
        """Proxy request to Qdrant with authentication"""
        try:
            # Extract token
            token = await self._get_token_from_request(request)
            if not token:
                raise HTTPException(status_code=401, detail="Authentication required")
            
            # Validate token
            try:
                payload = self.token_manager.validate_jwt_token(token)
                
                # Check if token is revoked
                token_id = payload.get("jti")
                if self.token_manager.is_token_revoked(token_id):
                    raise HTTPException(status_code=401, detail="Token has been revoked")
                
                # Validate permissions
                if not self._validate_permissions(payload, request):
                    raise HTTPException(status_code=403, detail="Insufficient permissions")
            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=401, detail="Token has expired")
            except jwt.InvalidTokenError:
                raise HTTPException(status_code=401, detail="Invalid token")
            
            # Forward request to Qdrant
            url = f"{self.qdrant_url}/{path}"
            if request.query_params:
                # Remove token from query params before forwarding
                filtered_params = {k: v for k, v in request.query_params.items() if k != "token"}
                if filtered_params:
                    url += "?" + "&".join([f"{k}={v}" for k, v in filtered_params.items()])
            
            # Get request body
            body = None
            if request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
            
            # Forward headers (excluding auth headers)
            headers = {k: v for k, v in request.headers.items() 
                      if k.lower() not in ["authorization", "x-api-key", "host"]}
            
            # Make request to Qdrant
            async with httpx.AsyncClient() as client:
                response = await client.request(
                    method=request.method,
                    url=url,
                    headers=headers,
                    content=body,
                    timeout=30.0
                )
            
            # Add authentication info to response headers
            response_headers = dict(response.headers)
            response_headers["X-Auth-User"] = payload.get("sub", "unknown")
            response_headers["X-Auth-Permissions"] = ",".join(payload.get("permissions", []))
            
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=response_headers,
                media_type=response.headers.get("content-type")
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Proxy error: {e}")
            raise HTTPException(status_code=500, detail="Internal proxy error")

def create_app(qdrant_host: str = "qdrant-internal.qdrant-system.svc.cluster.local", 
               qdrant_port: int = 6333) -> FastAPI:
    proxy = QdrantAuthProxy(qdrant_host, qdrant_port)
    return proxy.app

if __name__ == "__main__":
    import uvicorn
    import argparse
    
    parser = argparse.ArgumentParser(description="Qdrant Authentication Proxy")
    parser.add_argument("--host", default="0.0.0.0", help="Proxy host")
    parser.add_argument("--port", type=int, default=8000, help="Proxy port")
    parser.add_argument("--qdrant-host", default="localhost", help="Qdrant host")
    parser.add_argument("--qdrant-port", type=int, default=6333, help="Qdrant port")
    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    
    args = parser.parse_args()
    
    app = create_app(args.qdrant_host, args.qdrant_port)
    
    logger.info(f"Starting Qdrant Auth Proxy on {args.host}:{args.port}")
    logger.info(f"Proxying to Qdrant at {args.qdrant_host}:{args.qdrant_port}")
    
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        workers=args.workers,
        access_log=True
    )