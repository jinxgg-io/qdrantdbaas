#!/usr/bin/env python3
import sys
import yaml
import json
import click
import logging
import subprocess
from typing import Dict, Optional
from pathlib import Path

from k8s_deployer import QdrantK8sDeployer
from token_manager import QdrantAuthManager
import cloud_providers
from cloud_providers import create_provider

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QdrantDBaaSDeployer:
    def __init__(self, config_path: str = 'config.yaml'):
        self.config_path = config_path
        self.config = self._load_config()
        self.cloud_provider = None
        self.k8s_deployer = None
        self.auth_manager = None
        
    def _load_config(self) -> cloud_providers.DeploymentConfiguration:
        try:
            with open(self.config_path, 'r') as f:
                config_dict = yaml.safe_load(f)

            cloud_provider = config_dict.get("cloud_provider", "aws")
            
            # Create network configuration from cloud-agnostic VPC config
            vpc_config = config_dict.get("vpc", {})
            network_config = cloud_providers.NetworkConfiguration(
                vpc_cidr=vpc_config.get("cidr", "10.0.0.0/16"),
                public_subnets=vpc_config.get("public_subnets", ["10.0.1.0/24", "10.0.2.0/24"]),
                private_subnets=vpc_config.get("private_subnets", ["10.0.10.0/24", "10.0.20.0/24"])
            )
            
            if cloud_provider.lower() == "aws":
                aws_config = config_dict["aws"]
                eks_config = aws_config["eks"]
                
                # Create AWS credentials
                credentials = cloud_providers.AWSCredentials(
                    region=aws_config["region"],
                    profile=aws_config.get("profile")
                )
                
                # Create node groups
                node_groups = []
                for ng in eks_config["node_groups"]:
                    node_group = cloud_providers.NodeGroupConfiguration(
                        name=ng["name"],
                        instance_types=ng["instance_types"],
                        min_size=ng["min_size"],
                        max_size=ng["max_size"],
                        desired_size=ng["desired_size"],
                        disk_size=ng.get("disk_size", 50),
                        ami_type=ng.get("ami_type", "BOTTLEROCKET_x86_64"),
                        spot_instances=ng.get("capacity_type") == "SPOT"
                    )
                    node_groups.append(node_group)

                cluster_config = cloud_providers.KubernetesClusterConfiguration(
                    name=eks_config["cluster_name"],
                    version=eks_config["version"],
                    node_groups=node_groups,
                    network=network_config
                )
                
            else:
                raise ValueError(f"Unsupported cloud provider: {cloud_provider}")

            qdrant_dict = config_dict["qdrant"]
            
            qdrant_config = cloud_providers.QdrantConfiguration(
                namespace=qdrant_dict["namespace"],
                replicas=qdrant_dict["replicas"],
                image=qdrant_dict.get("image", "qdrant/qdrant:v1.8.1"),
                resources=qdrant_dict.get("resources", {}),
                storage_size=qdrant_dict.get("storage", {}).get("size", "10Gi"),
                storage_class=qdrant_dict.get("storage", {}).get("class", "gp3"),  # Default to gp3 if not specified
                service_type=qdrant_dict.get("service", {}).get("type", "LoadBalancer"),
                http_port=qdrant_dict.get("service", {}).get("port", 6333),
                grpc_port=qdrant_dict.get("service", {}).get("grpc_port", 6334),
                enable_authentication=True,
                enable_jwt_rbac=True
            )

            mapped_config = {
                "provider": cloud_providers.CloudProvider.AWS if cloud_provider.lower() == "aws" else cloud_provider,
                "credentials": credentials,
                "cluster": cluster_config,
                "qdrant": qdrant_config
            }

            config = cloud_providers.DeploymentConfiguration(**mapped_config)
            logger.info(f"Configuration loaded from {self.config_path}")
            return config
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"Error parsing configuration file: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error creating configuration model: {e}")
            sys.exit(1)
    
    def setup_kubectl_config(self, cluster_name: str, region: str) -> bool:
        logger.info("Configuring kubectl for EKS cluster...")
        
        try:
            cmd = [
                "aws", "eks", "update-kubeconfig",
                "--region", region,
                "--name", cluster_name
            ]
            
            if self.config.credentials.profile:
                cmd.extend(["--profile", self.config.credentials.profile])
            
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info("kubectl configured successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to configure kubectl: {e}")
            logger.error(f"Error output: {e.stderr}")
            return False
        except FileNotFoundError:
            logger.error("AWS CLI not found. Please install AWS CLI.")
            return False
    
    @staticmethod
    def _configure_kubectl_with_config(kubeconfig_content: str) -> bool:
        try:
            import tempfile
            import os

            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(kubeconfig_content)
                kubeconfig_path = f.name

            env = os.environ.copy()
            env['KUBECONFIG'] = kubeconfig_path
            
            subprocess.run(
                ['kubectl', 'cluster-info'], 
                env=env,
                capture_output=True, 
                text=True, 
                check=True
            )
            kubectl_dir = Path.home() / '.kube'
            kubectl_dir.mkdir(exist_ok=True)
            
            import shutil
            shutil.copy2(kubeconfig_path, kubectl_dir / 'config')

            os.unlink(kubeconfig_path)
            
            logger.info("kubectl configured successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to configure kubectl: {e}")
            return False
        except Exception as e:
            logger.error(f"Error configuring kubectl: {e}")
            return False

    def deploy_infrastructure(self) -> Dict:
        logger.info("Starting infrastructure deployment...")

        self.cloud_provider = create_provider(self.config.credentials)
        
        try:
            import asyncio
            result = asyncio.run(self.cloud_provider.create_cluster(self.config.cluster))
            
            if not result.success:
                raise Exception(f"Cluster creation failed: {result.error_message}")
            
            cluster_name = result.cluster_id or self.config.cluster.name
            logger.info(f"Cluster provisioned: {cluster_name}")

            kubeconfig = asyncio.run(self.cloud_provider.get_kubeconfig(cluster_name))
            if not self._configure_kubectl_with_config(kubeconfig):
                raise Exception("Failed to configure kubectl")

            return {
                'cluster_name': cluster_name,
                'cluster_arn': result.cluster_arn,
                'region': self.config.credentials.region,
                'success': True
            }
        except Exception as e:
            logger.error(f"Infrastructure deployment failed: {e}")
            raise e
    
    def setup_qdrant_authentication(self, namespace: str = "qdrant-system") -> Dict:
        logger.info("Setting up Qdrant authentication...")
        
        self.auth_manager = QdrantAuthManager()
        
        try:
            import base64
            
            # Base64 encode the keys
            api_key_b64 = base64.b64encode(self.auth_manager.api_key.encode()).decode()
            readonly_key_b64 = base64.b64encode(self.auth_manager.read_only_api_key.encode()).decode()
            
            # Create secret manifest
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
            
            if process.returncode != 0:
                raise Exception(f"Failed to create Kubernetes secret: {stderr}")
            
            auth_info = {
                'api_key': self.auth_manager.api_key,
                'read_only_api_key': self.auth_manager.read_only_api_key,
                'jwt_rbac_enabled': True,
                'namespace': namespace,
                'secret_created': True
            }
            
            logger.info("Qdrant authentication setup completed successfully")
            return auth_info
        except Exception as e:
            logger.error(f"Authentication setup failed: {e}")
            raise e
    
    def deploy_qdrant(self, infrastructure_info: Dict) -> Dict:
        logger.info("Starting Qdrant deployment...")

        self.k8s_deployer = QdrantK8sDeployer()

        namespace = self.config.qdrant.namespace
        if not self.k8s_deployer.create_namespace(namespace):
            raise Exception(f"Failed to create namespace: {namespace}")

        auth_info = self.setup_qdrant_authentication(namespace)
        
        try:
            result = self.k8s_deployer.deploy_qdrant(self.config.qdrant)
            result.update({
                'cluster_name': infrastructure_info['cluster_name'],
                'cluster_arn': infrastructure_info['cluster_arn'],
                'region': infrastructure_info['region'],
                'authentication': auth_info
            })
            
            return result
        except Exception as e:
            logger.error(f"Qdrant deployment failed: {e}")
            raise e
    
    @staticmethod
    def get_connection_info(deployment_result: Dict) -> Dict:
        logger.info("Retrieving connection information...")
        
        connection_info = {
            'cluster_name': deployment_result['cluster_name'],
            'namespace': deployment_result['namespace'],
            'region': deployment_result['region']
        }
        
        # LoadBalancer service info
        if deployment_result.get('loadbalancer_service'):
            lb_service = deployment_result['loadbalancer_service']
            if lb_service.get('external_ip'):
                connection_info['external_endpoint'] = {
                    'host': lb_service['external_ip'],
                    'http_port': 6333,
                    'grpc_port': 6334,
                    'http_url': f"http://{lb_service['external_ip']}:6333",
                    'grpc_url': f"{lb_service['external_ip']}:6334"
                }
        
        # Internal service info
        if deployment_result.get('internal_service'):
            connection_info['internal_endpoint'] = {
                'service_name': 'qdrant-internal',
                'namespace': deployment_result['namespace'],
                'http_port': 6333,
                'grpc_port': 6334,
                'http_url': f"http://qdrant-internal.{deployment_result['namespace']}.svc.cluster.local:6333",
                'grpc_url': f"qdrant-internal.{deployment_result['namespace']}.svc.cluster.local:6334"
            }
        
        return connection_info
    
    def save_deployment_info(self, deployment_result: Dict, connection_info: Dict):
        logger.info("Saving deployment information...")
        
        output_dir = Path("deployment_output")
        output_dir.mkdir(exist_ok=True)
        
        with open(output_dir / "deployment_result.json", "w") as f:
            json.dump(deployment_result, f, indent=2)
        
        with open(output_dir / "connection_info.json", "w") as f:
            json.dump(connection_info, f, indent=2)
        
        examples = self._create_connection_examples(connection_info)
        with open(output_dir / "connection_examples.md", "w") as f:
            f.write(examples)
        
        logger.info(f"Deployment information saved to {output_dir}")
    
    @staticmethod
    def _create_connection_examples(connection_info: Dict) -> str:
        examples = f"""# Qdrant DBaaS Connection Examples

## Cluster Information
- **Cluster Name**: {connection_info.get('cluster_name', 'N/A')}
- **Namespace**: {connection_info.get('namespace', 'N/A')}
- **Region**: {connection_info.get('region', 'N/A')}

"""
        
        if connection_info.get('external_endpoint'):
            ext = connection_info['external_endpoint']
            auth_info = connection_info.get('authentication', {})
            api_key = auth_info.get('api_key', 'your-api-key-here')
            readonly_key = auth_info.get('read_only_api_key', 'your-readonly-key-here')
            
            examples += f"""## External Access (LoadBalancer)

### HTTP API
- **URL**: {ext.get('http_url', 'N/A')}
- **Host**: {ext.get('host', 'N/A')}
- **Port**: {ext.get('http_port', 'N/A')}

### gRPC API
- **URL**: {ext.get('grpc_url', 'N/A')}
- **Host**: {ext.get('host', 'N/A')}
- **Port**: {ext.get('grpc_port', 'N/A')}

### Authentication
- **Master API Key**: `{api_key}`
- **Read-Only API Key**: `{readonly_key}`
- **JWT RBAC**: Enabled

### Python Example (External with API Key)
```python
from qdrant_client import QdrantClient

# HTTP client with API key authentication
client = QdrantClient(
    host="{ext.get('host', 'your-loadbalancer-host')}",
    port={ext.get('http_port', 6333)},
    api_key="{api_key}"
)

# Read-only client
readonly_client = QdrantClient(
    host="{ext.get('host', 'your-loadbalancer-host')}",
    port={ext.get('http_port', 6333)},
    api_key="{readonly_key}"
)

# gRPC client with API key
grpc_client = QdrantClient(
    host="{ext.get('host', 'your-loadbalancer-host')}",
    port={ext.get('grpc_port', 6334)},
    grpc_port={ext.get('grpc_port', 6334)},
    api_key="{api_key}",
    prefer_grpc=True
)

# Test connection
print(client.get_collections())
```

### curl Examples (External)
```bash
# Using API key header
curl -H "api-key: {api_key}" "{ext.get('http_url', 'http://your-host:6333')}/collections"

# Using read-only key
curl -H "api-key: {readonly_key}" "{ext.get('http_url', 'http://your-host:6333')}/collections"
```

"""
        
        if connection_info.get('internal_endpoint'):
            int_ep = connection_info['internal_endpoint']
            examples += f"""## Internal Access (ClusterIP)

### HTTP API
- **URL**: {int_ep.get('http_url', 'N/A')}
- **Port**: {int_ep.get('http_port', 'N/A')}

### gRPC API
- **URL**: {int_ep.get('grpc_url', 'N/A')}
- **Port**: {int_ep.get('grpc_port', 'N/A')}

### Python Example (Internal - from within cluster)
```python
from qdrant_client import QdrantClient

# HTTP client
client = QdrantClient(
    url="{int_ep.get('http_url', 'http://qdrant-internal.qdrant-system.svc.cluster.local:6333')}"
)

# gRPC client
client = QdrantClient(
    host="qdrant-internal.{connection_info.get('namespace', 'qdrant-system')}.svc.cluster.local",
    port={int_ep.get('grpc_port', 6334)},
    prefer_grpc=True
)
```

### kubectl Port Forward (for development)
```bash
# Forward HTTP port
kubectl port-forward -n {connection_info.get('namespace', 'qdrant-system')} svc/qdrant-internal 6333:6333

# Forward gRPC port
kubectl port-forward -n {connection_info.get('namespace', 'qdrant-system')} svc/qdrant-internal 6334:6334

# Then connect to localhost
curl http://localhost:6333/collections
```

"""
        
        examples += """## Management Commands

### Check Deployment Status
```bash
kubectl get pods -n qdrant-system
kubectl get svc -n qdrant-system
kubectl get pvc -n qdrant-system
```

### View Logs
```bash
kubectl logs -n qdrant-system -l app=qdrant -f
```

### Scale Deployment
```bash
kubectl scale statefulset qdrant -n qdrant-system --replicas=3
```

### Access Pod Directly
```bash
kubectl exec -it -n qdrant-system qdrant-0 -- /bin/bash
```

## Troubleshooting

If you can't connect:
1. Check if the LoadBalancer has been assigned an external IP
2. Verify security groups allow traffic on ports 6333 and 6334
3. Check pod status and logs
4. Ensure the EBS CSI driver is installed for persistent storage
"""
        
        return examples
    
    def full_deployment(self) -> Dict:
        logger.info("Starting full Qdrant DBaaS deployment...")
        
        try:
            infrastructure_result = self.deploy_infrastructure()
            qdrant_result = self.deploy_qdrant(infrastructure_result)
            connection_info = self.get_connection_info(qdrant_result)
            
            self.save_deployment_info(qdrant_result, connection_info)
            
            logger.info("=== Deployment Completed Successfully! ===")
            logger.info(f"Cluster Name: {qdrant_result['cluster_name']}")
            logger.info(f"Namespace: {qdrant_result['namespace']}")
            logger.info(f"Region: {qdrant_result['region']}")
            
            if connection_info.get('external_endpoint'):
                ext = connection_info['external_endpoint']
                logger.info(f"External HTTP URL: {ext.get('http_url', 'N/A')}")
                logger.info(f"External gRPC URL: {ext.get('grpc_url', 'N/A')}")
            
            logger.info("Check 'deployment_output/' directory for detailed connection information")
            
            return {
                'status': 'success',
                'deployment': qdrant_result,
                'connection': connection_info
            }
        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    def cleanup_deployment(self, cluster_name: Optional[str] = None):
        if not cluster_name:
            cluster_name = self.config.cluster.name
        
        logger.info(f"Cleaning up deployment: {cluster_name}")
        
        try:
            # Clean up Qdrant resources first
            if self.k8s_deployer or self.setup_kubectl_config(cluster_name, self.config.credentials.region):
                deployer = QdrantK8sDeployer()
                deployer.delete_qdrant(self.config.qdrant.namespace)
            
            # Use cloud provider to delete cluster
            if self.cloud_provider:
                import asyncio
                success = asyncio.run(self.cloud_provider.delete_cluster(cluster_name, force=True))
                if not success:
                    logger.warning(f"Failed to delete cluster {cluster_name}")
            
            logger.info("Cleanup completed successfully")
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            raise e

@click.group()
def cli():
    """Qdrant DBaaS Deployment Tool"""
    pass

@cli.command()
@click.option('--config', '-c', default='config.yaml', help='Configuration file path')
def deploy(config):
    deployer = QdrantDBaaSDeployer(config)
    result = deployer.full_deployment()
    
    if result['status'] == 'success':
        click.echo("✅ Deployment completed successfully!")
        sys.exit(0)
    else:
        click.echo(f"❌ Deployment failed: {result['error']}")
        sys.exit(1)

@cli.command()
@click.option('--config', '-c', default='config.yaml', help='Configuration file path')
def deploy_infra(config):
    deployer = QdrantDBaaSDeployer(config)
    result = deployer.deploy_infrastructure()
    click.echo(f"Infrastructure deployed: {result}")

@cli.command()
@click.option('--config', '-c', default='config.yaml', help='Configuration file path')
def deploy_app(config):
    deployer = QdrantDBaaSDeployer(config)
    
    # Setup kubectl
    cluster_name = deployer.config.cluster.name
    region = deployer.config.credentials.region
    
    if not deployer.setup_kubectl_config(cluster_name, region):
        click.echo("❌ Failed to configure kubectl")
        sys.exit(1)
    
    # Mock infrastructure info
    infrastructure_info = {
        'cluster_name': cluster_name,
        'cluster_arn': f"arn:aws:eks:{region}:123456789012:cluster/{cluster_name}",
        'region': region
    }
    
    result = deployer.deploy_qdrant(infrastructure_info)
    connection_info = deployer.get_connection_info(result)
    deployer.save_deployment_info(result, connection_info)
    
    click.echo("✅ Qdrant deployment completed successfully!")

@cli.command()
@click.option('--config', '-c', default='config.yaml', help='Configuration file path')
@click.option('--cluster-name', help='Cluster name to cleanup (optional)')
def cleanup(config, cluster_name):
    deployer = QdrantDBaaSDeployer(config)
    deployer.cleanup_deployment(cluster_name)
    click.echo("✅ Cleanup completed!")

@cli.command()
@click.option('--config', '-c', default='config.yaml', help='Configuration file path')
def status(config):
    deployer = QdrantDBaaSDeployer(config)
    
    cluster_name = deployer.config.cluster.name
    namespace = deployer.config.qdrant.namespace
    region = deployer.config.credentials.region
    
    click.echo(f"Cluster: {cluster_name}")
    click.echo(f"Namespace: {namespace}")
    click.echo(f"Region: {region}")
    
    # Try to get cluster status
    try:
        if deployer.setup_kubectl_config(cluster_name, region):
            k8s_deployer = QdrantK8sDeployer()
            
            # Check if deployment exists
            lb_service = k8s_deployer.get_service_endpoint(namespace, 'qdrant')
            if lb_service:
                click.echo("✅ Qdrant is deployed")
                click.echo(f"LoadBalancer service: {lb_service}")
            else:
                click.echo("❌ Qdrant not found")
        else:
            click.echo("❌ Cannot connect to cluster")
    except Exception as e:
        click.echo(f"❌ Error checking status: {e}")

if __name__ == "__main__":
    cli()