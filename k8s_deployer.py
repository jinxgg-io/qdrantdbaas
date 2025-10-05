#!/usr/bin/env python3
import logging
import os
import time
import yaml
from typing import Dict, List, Optional

from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.config.config_exception import ConfigException
from cloud_providers import QdrantConfiguration

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QdrantK8sDeployer:
    _sleep_interval = 10

    def __init__(self, kubeconfig_path: Optional[str] = None):
        try:
            if kubeconfig_path:
                config.load_kube_config(config_file=kubeconfig_path)
            else:
                try:
                    config.load_kube_config()
                except ConfigException:
                    config.load_incluster_config()
            
            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.storage_v1 = client.StorageV1Api()
            self.rbac_v1 = client.RbacAuthorizationV1Api()
            
            logger.info("Kubernetes client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Kubernetes client: {e}")
            raise e

    @staticmethod
    def load_manifests(manifest_path: str) -> List[Dict]:
        with open(manifest_path, 'r') as mf:
            manifests = list(yaml.safe_load_all(mf))
        
        return [m for m in manifests if m is not None]

    def create_namespace(self, namespace_name: str) -> bool:
        try:
            self.v1.read_namespace(name=namespace_name)
            logger.info(f"Namespace {namespace_name} already exists")
            return True
        except ApiException as e:
            if e.status == 404:
                namespace = client.V1Namespace(
                    metadata=client.V1ObjectMeta(
                        name=namespace_name,
                        labels={
                            "app": "qdrant",
                            "environment": "dbaas"
                        }
                    )
                )
                
                try:
                    self.v1.create_namespace(body=namespace)
                    logger.info(f"Created namespace: {namespace_name}")
                    return True
                except ApiException as create_error:
                    logger.error(f"Failed to create namespace {namespace_name}: {create_error}")
                    return False
            else:
                logger.error(f"Error checking namespace {namespace_name}: {e}")
                return False

    def apply_manifest_resource(self, resource: Dict, namespace: str = None) -> bool:
        kind = resource.get('kind')
        metadata = resource.get('metadata', {})
        name = metadata.get('name')
        
        if namespace and 'namespace' not in metadata:
            resource['metadata']['namespace'] = namespace
        
        logger.info(f"Applying {kind}: {name}")
        
        try:
            if kind == 'Namespace':
                return self._apply_namespace(resource)
            elif kind == 'ConfigMap':
                return self._apply_configmap(resource)
            elif kind == 'StorageClass':
                return self._apply_storageclass(resource)
            elif kind == 'PersistentVolumeClaim':
                return self._apply_pvc(resource)
            elif kind == 'ServiceAccount':
                return self._apply_serviceaccount(resource)
            elif kind == 'ClusterRole':
                return self._apply_clusterrole(resource)
            elif kind == 'ClusterRoleBinding':
                return self._apply_clusterrolebinding(resource)
            elif kind == 'Service':
                return self._apply_service(resource)
            elif kind == 'StatefulSet':
                return self._apply_statefulset(resource)
            else:
                logger.warning(f"Unsupported resource kind: {kind}")
                return False
        except ApiException as e:
            logger.error(f"Failed to apply {kind} {name}: {e}")
            return False

    def _apply_namespace(self, resource: Dict) -> bool:
        namespace = client.V1Namespace(**resource)
        try:
            self.v1.create_namespace(body=namespace)
            logger.info(f"Created namespace: {resource['metadata']['name']}")
            return True
        except ApiException as e:
            if e.status == 409:  # Already exists
                logger.info(f"Namespace {resource['metadata']['name']} already exists")
                return True
            raise e

    def _apply_configmap(self, resource: Dict) -> bool:
        namespace = resource['metadata']['namespace']
        name = resource['metadata']['name']
        
        try:
            self.v1.read_namespaced_config_map(name=name, namespace=namespace)
            # Update existing
            body = client.V1ConfigMap(**resource)
            self.v1.patch_namespaced_config_map(name=name, namespace=namespace, body=body)
            logger.info(f"Updated ConfigMap: {name}")
        except ApiException as e:
            if e.status == 404:
                # Create new
                body = client.V1ConfigMap(**resource)
                self.v1.create_namespaced_config_map(namespace=namespace, body=body)
                logger.info(f"Created ConfigMap: {name}")
            else:
                raise e
        return True

    def _apply_storageclass(self, resource: Dict) -> bool:
        name = resource['metadata']['name']
        
        try:
            self.storage_v1.read_storage_class(name=name)
            logger.info(f"StorageClass {name} already exists")
        except ApiException as e:
            if e.status == 404:
                body = client.V1StorageClass(**resource)
                self.storage_v1.create_storage_class(body=body)
                logger.info(f"Created StorageClass: {name}")
            else:
                raise e
        return True

    def _apply_pvc(self, resource: Dict) -> bool:
        namespace = resource['metadata']['namespace']
        name = resource['metadata']['name']
        
        try:
            self.v1.read_namespaced_persistent_volume_claim(name=name, namespace=namespace)
            logger.info(f"PVC {name} already exists")
        except ApiException as e:
            if e.status == 404:
                body = client.V1PersistentVolumeClaim(**resource)
                self.v1.create_namespaced_persistent_volume_claim(namespace=namespace, body=body)
                logger.info(f"Created PVC: {name}")
            else:
                raise e
        return True

    def _apply_serviceaccount(self, resource: Dict) -> bool:
        namespace = resource['metadata']['namespace']
        name = resource['metadata']['name']
        
        try:
            self.v1.read_namespaced_service_account(name=name, namespace=namespace)
            logger.info(f"ServiceAccount {name} already exists")
        except ApiException as e:
            if e.status == 404:
                body = client.V1ServiceAccount(**resource)
                self.v1.create_namespaced_service_account(namespace=namespace, body=body)
                logger.info(f"Created ServiceAccount: {name}")
            else:
                raise e
        return True

    def _apply_clusterrole(self, resource: Dict) -> bool:
        name = resource['metadata']['name']
        
        try:
            self.rbac_v1.read_cluster_role(name=name)
            logger.info(f"ClusterRole {name} already exists")
        except ApiException as e:
            if e.status == 404:
                body = client.V1ClusterRole(**resource)
                self.rbac_v1.create_cluster_role(body=body)
                logger.info(f"Created ClusterRole: {name}")
            else:
                raise e
        return True

    def _apply_clusterrolebinding(self, resource: Dict) -> bool:
        name = resource['metadata']['name']
        
        try:
            self.rbac_v1.read_cluster_role_binding(name=name)
            logger.info(f"ClusterRoleBinding {name} already exists")
        except ApiException as e:
            if e.status == 404:
                body = client.V1ClusterRoleBinding(**resource)
                self.rbac_v1.create_cluster_role_binding(body=body)
                logger.info(f"Created ClusterRoleBinding: {name}")
            else:
                raise e
        return True

    def _apply_service(self, resource: Dict) -> bool:
        namespace = resource['metadata']['namespace']
        name = resource['metadata']['name']
        
        try:
            self.v1.read_namespaced_service(name=name, namespace=namespace)
            # Update existing
            body = client.V1Service(**resource)
            self.v1.patch_namespaced_service(name=name, namespace=namespace, body=body)
            logger.info(f"Updated Service: {name}")
        except ApiException as e:
            if e.status == 404:
                # Create new
                body = client.V1Service(**resource)
                self.v1.create_namespaced_service(namespace=namespace, body=body)
                logger.info(f"Created Service: {name}")
            else:
                raise e
        return True

    def _apply_statefulset(self, resource: Dict) -> bool:
        namespace = resource['metadata']['namespace']
        name = resource['metadata']['name']
        
        try:
            self.apps_v1.read_namespaced_stateful_set(name=name, namespace=namespace)
            # Update existing
            body = client.V1StatefulSet(**resource)
            self.apps_v1.patch_namespaced_stateful_set(name=name, namespace=namespace, body=body)
            logger.info(f"Updated StatefulSet: {name}")
        except ApiException as e:
            if e.status == 404:
                # Create new
                body = client.V1StatefulSet(**resource)
                self.apps_v1.create_namespaced_stateful_set(namespace=namespace, body=body)
                logger.info(f"Created StatefulSet: {name}")
            else:
                raise e
        return True

    def apply_manifests(self, manifest_dir: str, namespace: str = None) -> bool:
        logger.info(f"Applying manifests from {manifest_dir}")
        
        # Order of manifest files to apply
        manifest_order = [
            'namespace.yaml',
            'configmap.yaml',
            'storageclass.yaml',
            'storage.yaml',
            'statefulset.yaml',
            'services.yaml'
        ]
        
        success = True
        for manifest_file in manifest_order:
            manifest_path = os.path.join(manifest_dir, manifest_file)

            if not os.path.exists(manifest_path):
                logger.warning(f"Manifest file not found: {manifest_path}")
                continue
            
            logger.info(f"Applying manifest: {manifest_file}")
            
            try:
                # Use kubectl apply instead of Python client to avoid YAML parsing issues
                import subprocess
                result = subprocess.run(
                    ['kubectl', 'apply', '-f', manifest_path],
                    capture_output=True, text=True, check=False
                )
                
                if result.returncode != 0:
                    logger.error(f"Failed to apply {manifest_file}: {result.stderr}")
                    success = False
                else:
                    logger.info(f"Successfully applied {manifest_file}: {result.stdout.strip()}")
                    
            except Exception as e:
                logger.error(f"Error processing manifest {manifest_file}: {e}")
                success = False
        
        return success

    def wait_for_deployment(self, namespace: str, statefulset_name: str, timeout: int = 600) -> bool:
        logger.info(f"Waiting for StatefulSet {statefulset_name} to be ready...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                statefulset = self.apps_v1.read_namespaced_stateful_set(
                    name=statefulset_name, 
                    namespace=namespace
                )
                
                ready_replicas = statefulset.status.ready_replicas or 0
                replicas = statefulset.spec.replicas
                
                logger.info(f"StatefulSet {statefulset_name}: {ready_replicas}/{replicas} pods ready")
                
                if ready_replicas == replicas:
                    logger.info(f"StatefulSet {statefulset_name} is ready!")
                    return True
            except ApiException as e:
                logger.error(f"Error checking StatefulSet status: {e}")
            time.sleep(QdrantK8sDeployer._sleep_interval)
        
        logger.error(f"Timeout waiting for StatefulSet {statefulset_name}")
        return False

    def get_service_endpoint(self, namespace: str, service_name: str) -> Optional[Dict]:
        try:
            service = self.v1.read_namespaced_service(name=service_name, namespace=namespace)
            
            endpoint_info = {
                'name': service_name,
                'namespace': namespace,
                'type': service.spec.type,
                'ports': []
            }
            
            for port in service.spec.ports:
                port_info = {
                    'name': port.name,
                    'port': port.port,
                    'target_port': port.target_port,
                    'protocol': port.protocol
                }
                endpoint_info['ports'].append(port_info)
            
            if service.spec.type == 'LoadBalancer':
                if service.status.load_balancer and service.status.load_balancer.ingress:
                    ingress = service.status.load_balancer.ingress[0]
                    endpoint_info['external_ip'] = ingress.ip or ingress.hostname
            elif service.spec.type == 'ClusterIP':
                endpoint_info['cluster_ip'] = service.spec.cluster_ip
            
            return endpoint_info
        except ApiException as e:
            logger.error(f"Error getting service endpoint: {e}")
            return None

    def deploy_qdrant(self, qdrant_config: QdrantConfiguration) -> Dict:
        logger.info("Starting Qdrant deployment...")
        
        namespace = qdrant_config.namespace
        # Create namespace
        if not self.create_namespace(namespace):
            raise Exception(f"Failed to create namespace: {namespace}")
        
        # Apply manifests
        if not self.apply_manifests('./k8s', namespace):
            raise Exception("Failed to apply Kubernetes manifests")
        
        # Wait for deployment
        if not self.wait_for_deployment(namespace, 'qdrant', timeout=600):
            raise Exception("Deployment failed or timed out")
        
        # Get service endpoints
        lb_service = self.get_service_endpoint(namespace, 'qdrant')
        internal_service = self.get_service_endpoint(namespace, 'qdrant-internal')
        
        deployer_result = {
            'status': 'deployed',
            'namespace': namespace,
            'loadbalancer_service': lb_service,
            'internal_service': internal_service
        }
        
        logger.info("Qdrant deployment completed successfully!")
        return deployer_result

    def delete_qdrant(self, namespace: str) -> bool:
        logger.info(f"Deleting Qdrant deployment from namespace: {namespace}")
        
        try:
            # Delete StatefulSet
            try:
                self.apps_v1.delete_namespaced_stateful_set(
                    name='qdrant', 
                    namespace=namespace
                )
                logger.info("Deleted StatefulSet: qdrant")
            except ApiException as e:
                if e.status != 404:
                    logger.error(f"Error deleting StatefulSet: {e}")
            
            # Delete Services
            services = ['qdrant', 'qdrant-internal', 'qdrant-headless']
            for service in services:
                try:
                    self.v1.delete_namespaced_service(name=service, namespace=namespace)
                    logger.info(f"Deleted Service: {service}")
                except ApiException as e:
                    if e.status != 404:
                        logger.error(f"Error deleting Service {service}: {e}")
            
            # Delete ConfigMap
            try:
                self.v1.delete_namespaced_config_map(name='qdrant-config', namespace=namespace)
                logger.info("Deleted ConfigMap: qdrant-config")
            except ApiException as e:
                if e.status != 404:
                    logger.error(f"Error deleting ConfigMap: {e}")
            
            # Delete PVCs
            try:
                pvcs = self.v1.list_namespaced_persistent_volume_claim(namespace=namespace)
                for pvc in pvcs.items:
                    if pvc.metadata.name.startswith('qdrant'):
                        self.v1.delete_namespaced_persistent_volume_claim(
                            name=pvc.metadata.name,
                            namespace=namespace
                        )
                        logger.info(f"Deleted PVC: {pvc.metadata.name}")
            except ApiException as e:
                logger.error(f"Error deleting PVCs: {e}")
            
            logger.info("Qdrant deployment deleted successfully")
            return True
        except Exception as e:
            logger.error(f"Error during deletion: {e}")
            return False

if __name__ == "__main__":
    # Load configuration
    with open('config.yaml', 'r') as f:
        config_data = yaml.safe_load(f)
    
    from cloud_providers import DeploymentConfiguration
    config = DeploymentConfiguration(**config_data)
    
    # Create deployer
    deployer = QdrantK8sDeployer()
    
    # Deploy Qdrant
    result = deployer.deploy_qdrant(config.qdrant)
    print(f"Deployment result: {result}")
