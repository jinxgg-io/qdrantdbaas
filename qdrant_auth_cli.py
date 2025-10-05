#!/usr/bin/env python3
import base64
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import click

# Add current directory to path for local imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from token_manager import QdrantAuthManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QdrantAuthCLI:
    def __init__(self):
        """Initialize the authentication CLI"""
        self.auth_manager = None
        self.config_file = Path("qdrant_auth_config.json")
        
    def load_auth_manager(self, api_key: Optional[str] = None, read_only_api_key: Optional[str] = None):
        """Load or create authentication manager"""
        if self.auth_manager is None:
            self.auth_manager = QdrantAuthManager(
                api_key=api_key,
                read_only_api_key=read_only_api_key
            )
        return self.auth_manager
    
    def save_keys_to_kubernetes_secret(self, namespace: str = "qdrant-system"):
        """Save API keys to Kubernetes secret"""
        try:
            import subprocess
            
            # Base64 encode the keys
            api_key_b64 = base64.b64encode(self.auth_manager.api_key.encode()).decode()
            readonly_key_b64 = base64.b64encode(self.auth_manager.read_only_api_key.encode()).decode()
            
            # Update Kubernetes secret
            secret_data = f"""
apiVersion: v1
kind: Secret
metadata:
  name: qdrant-api-keys
  namespace: {namespace}
  labels:
    app: qdrant
type: Opaque
data:
  api_key: {api_key_b64}
  read_only_api_key: {readonly_key_b64}
"""
            
            # Apply the secret
            process = subprocess.Popen(['kubectl', 'apply', '-f', '-'], 
                                     stdin=subprocess.PIPE, 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     text=True)
            stdout, stderr = process.communicate(input=secret_data)
            
            if process.returncode == 0:
                logger.info(f"Successfully updated Kubernetes secret in namespace {namespace}")
                return True
            else:
                logger.error(f"Failed to update Kubernetes secret: {stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating Kubernetes secret: {e}")
            return False
    
    @staticmethod
    def get_qdrant_service_url(namespace: str = "qdrant-system") -> Optional[str]:
        """Get Qdrant service URL from Kubernetes"""
        try:
            import subprocess
            
            # Get service information
            result = subprocess.run([
                'kubectl', 'get', 'service', 'qdrant', 
                '-n', namespace, 
                '-o', 'jsonpath={.status.loadBalancer.ingress[0].hostname}{.status.loadBalancer.ingress[0].ip}'
            ], capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                external_host = result.stdout.strip()
                return f"http://{external_host}:6333"
            else:
                # Fallback to port-forward or internal service
                logger.warning("External LoadBalancer not available, use port-forward or internal service")
                return "http://localhost:6333"
                
        except Exception as e:
            logger.error(f"Error getting service URL: {e}")
            return None

@click.group()
@click.option('--api-key', help='Master API key (generated if not provided)')
@click.option('--read-only-key', help='Read-only API key (generated if not provided)')
@click.pass_context
def cli(ctx, api_key, read_only_key):
    """Qdrant Authentication Management CLI"""
    ctx.ensure_object(dict)
    ctx.obj['cli'] = QdrantAuthCLI()
    ctx.obj['api_key'] = api_key
    ctx.obj['read_only_key'] = read_only_key

@cli.command()
@click.option('--namespace', '-n', default='qdrant-system', help='Kubernetes namespace')
@click.option('--save-to-k8s/--no-save-to-k8s', default=True, help='Save keys to Kubernetes secret')
@click.pass_context
def setup(ctx, namespace, save_to_k8s):
    """Initialize Qdrant authentication with API keys"""
    cli_obj = ctx.obj['cli']
    
    # Load or create auth manager
    auth_manager = cli_obj.load_auth_manager(
        api_key=ctx.obj['api_key'],
        read_only_api_key=ctx.obj['read_only_key']
    )
    
    click.echo("🔐 Qdrant Authentication Setup")
    click.echo("=" * 40)
    click.echo(f"Master API Key: {auth_manager.api_key}")
    click.echo(f"Read-Only API Key: {auth_manager.read_only_api_key}")
    click.echo(f"JWT RBAC Enabled: {auth_manager.config['jwt_rbac_enabled']}")
    
    if save_to_k8s:
        click.echo(f"\n🚀 Saving keys to Kubernetes secret in namespace '{namespace}'...")
        if cli_obj.save_keys_to_kubernetes_secret(namespace):
            click.echo("✅ Keys saved to Kubernetes successfully!")
            click.echo("\n⚠️  Remember to restart Qdrant pods to pick up the new keys:")
            click.echo(f"   kubectl rollout restart statefulset/qdrant -n {namespace}")
        else:
            click.echo("❌ Failed to save keys to Kubernetes")
    
    # Save config locally
    config_file = Path("qdrant_deployment_config.json")
    config = {
        "api_key": auth_manager.api_key,
        "read_only_api_key": auth_manager.read_only_api_key,
        "namespace": namespace,
        "jwt_rbac_enabled": True
    }
    
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    click.echo(f"\n💾 Configuration saved to {config_file}")

@cli.command()
@click.option('--user-id', '-u', required=True, help='User identifier')
@click.option('--access-level', '-a', default='read', 
              type=click.Choice(['read', 'write', 'manage']), 
              help='Access level')
@click.option('--expiry-hours', '-e', default=24, type=int, help='Token expiry in hours')
@click.option('--collection', '-c', multiple=True, help='Allowed collections (can be specified multiple times)')
@click.option('--collection-access', default='r', 
              type=click.Choice(['r', 'rw']), 
              help='Access level for specified collections')
@click.pass_context
def create_token(ctx, user_id, access_level, expiry_hours, collection, collection_access):
    """Create a JWT token for Qdrant access"""
    cli_obj = ctx.obj['cli']
    auth_manager = cli_obj.load_auth_manager(
        api_key=ctx.obj['api_key'],
        read_only_api_key=ctx.obj['read_only_key']
    )
    
    # Build collection access list
    collections = None
    if collection:
        collections = [
            {
                "collection": col,
                "access": collection_access
            }
            for col in collection
        ]
    
    try:
        token_info = auth_manager.generate_jwt_token(
            user_id=user_id,
            access_level=access_level,
            expiry_hours=expiry_hours,
            collections=collections
        )
        
        click.echo("🎟️  JWT Token Generated")
        click.echo("=" * 30)
        click.echo(f"Token: {token_info['token']}")
        click.echo(f"User ID: {token_info['user_id']}")
        click.echo(f"Access Level: {token_info['access_level']}")
        click.echo(f"Expires At: {token_info['expires_at']}")
        click.echo(f"Expires In: {token_info['expires_in_seconds']} seconds")
        
        if collections:
            click.echo(f"Collections: {collections}")
        
        click.echo("\n📋 Usage Examples:")
        click.echo(f"curl -H 'Api-Key: {token_info['token']}' http://your-qdrant-host:6333/collections")
        click.echo(f"curl -H 'Authorization: Bearer {token_info['token']}' http://your-qdrant-host:6333/collections")
        
    except Exception as e:
        click.echo(f"❌ Error creating token: {e}")

@cli.command()
@click.option('--token', '-t', required=True, help='JWT token to validate')
@click.pass_context
def validate_token(ctx, token):
    """Validate a JWT token"""
    cli_obj = ctx.obj['cli']
    auth_manager = cli_obj.load_auth_manager(
        api_key=ctx.obj['api_key'],
        read_only_api_key=ctx.obj['read_only_key']
    )
    
    try:
        payload = auth_manager.validate_jwt_token(token)
        
        click.echo("✅ Token Valid")
        click.echo("=" * 15)
        click.echo(json.dumps(payload, indent=2, default=str))
        
    except Exception as e:
        click.echo(f"❌ Token Invalid: {e}")

@cli.command()
@click.option('--endpoint', '-e', default='/collections', help='API endpoint')
@click.option('--method', '-m', default='GET', help='HTTP method')
@click.option('--user-id', '-u', default='anonymous', help='User identifier')
@click.option('--access-level', '-a', default='read', 
              type=click.Choice(['read', 'write', 'manage']), 
              help='Access level')
@click.option('--expiry-hours', default=1, type=int, help='URL expiry in hours')
@click.option('--base-url', help='Base URL (auto-detected from k8s if not provided)')
@click.option('--namespace', '-n', default='qdrant-system', help='Kubernetes namespace')
@click.pass_context
def presign_url(ctx, endpoint, method, user_id, access_level, expiry_hours, base_url, namespace):
    """Generate a pre-signed URL"""
    cli_obj = ctx.obj['cli']
    auth_manager = cli_obj.load_auth_manager(
        api_key=ctx.obj['api_key'],
        read_only_api_key=ctx.obj['read_only_key']
    )
    
    # Get base URL if not provided
    if not base_url:
        base_url = cli_obj.get_qdrant_service_url(namespace)
        if not base_url:
            click.echo("❌ Could not determine Qdrant service URL")
            return
    
    try:
        presigned_info = auth_manager.generate_presigned_url(
            base_url=base_url,
            endpoint=endpoint,
            method=method,
            user_id=user_id,
            access_level=access_level,
            expiry_hours=expiry_hours
        )
        
        click.echo("🔗 Pre-signed URL Generated")
        click.echo("=" * 30)
        click.echo(f"URL: {presigned_info['url']}")
        click.echo(f"Method: {presigned_info['method']}")
        click.echo(f"Expires At: {presigned_info['expires_at']}")
        click.echo(f"Access Level: {presigned_info['access_level']}")
        
        click.echo("\n📋 Usage Examples:")
        for key, instruction in presigned_info['usage_instructions'].items():
            click.echo(f"{key}: {instruction}")
        
    except Exception as e:
        click.echo(f"❌ Error generating pre-signed URL: {e}")

@cli.command()
@click.option('--namespace', '-n', default='qdrant-system', help='Kubernetes namespace')
@click.pass_context
def test_connection(ctx, namespace):
    """Test connection to Qdrant with current API keys"""
    cli_obj = ctx.obj['cli']
    auth_manager = cli_obj._load_auth_manager(
        api_key=ctx.obj['api_key'],
        read_only_api_key=ctx.obj['read_only_key']
    )
    
    # Get service URL
    qdrant_url = cli_obj._get_qdrant_service_url(namespace)
    if not qdrant_url:
        click.echo("❌ Could not determine Qdrant service URL")
        return
    
    click.echo(f"🔍 Testing connection to {qdrant_url}")
    
    try:
        results = auth_manager.test_qdrant_connection(qdrant_url)
        
        click.echo("\n📊 Connection Test Results")
        click.echo("=" * 30)
        click.echo(f"Qdrant URL: {results['qdrant_url']}")
        click.echo(f"Master Key Valid: {'✅' if results['master_key_valid'] else '❌'}")
        click.echo(f"Read-only Key Valid: {'✅' if results['readonly_key_valid'] else '❌'}")
        
        if results['version']:
            click.echo(f"Qdrant Version: {results['version']}")
        
        if results['error']:
            click.echo(f"Error: {results['error']}")
            
    except Exception as e:
        click.echo(f"❌ Connection test failed: {e}")

@cli.command()
@click.pass_context
def show_config(ctx):
    """Show current authentication configuration"""
    cli_obj = ctx.obj['cli']
    auth_manager = cli_obj.load_auth_manager(
        api_key=ctx.obj['api_key'],
        read_only_api_key=ctx.obj['read_only_key']
    )
    
    click.echo("⚙️  Current Configuration")
    click.echo("=" * 25)
    click.echo(json.dumps(auth_manager.config, indent=2, default=str))

if __name__ == '__main__':
    cli()