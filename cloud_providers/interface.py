#!/usr/bin/env python3

from abc import ABC, abstractmethod
from typing import Dict, List, Any
from .models import (
    CloudCredentials,
    CloudProvider,
    KubernetesClusterConfiguration,
    NodeGroupConfiguration,
    DeploymentResult,
    ClusterState,
    NodeGroupState
)

class CloudProviderInterface(ABC):
    
    def __init__(self, credentials: CloudCredentials):
        self.credentials = credentials
        self.region = credentials.region
    
    @property
    @abstractmethod
    def provider_type(self) -> CloudProvider:
        pass
    
    @abstractmethod
    async def validate_credentials(self) -> bool:
        pass
    
    @abstractmethod
    async def create_cluster(self, config: KubernetesClusterConfiguration) -> DeploymentResult:
        pass
    
    @abstractmethod
    async def get_cluster_status(self, cluster_name: str) -> ClusterState:
        pass
    
    @abstractmethod
    async def update_cluster(self, cluster_name: str, config: KubernetesClusterConfiguration) -> DeploymentResult:
        pass
    
    @abstractmethod
    async def delete_cluster(self, cluster_name: str, force: bool = False) -> bool:
        pass
    
    @abstractmethod
    async def create_node_group(self, cluster_name: str, config: NodeGroupConfiguration) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    async def get_node_group_status(self, cluster_name: str, node_group_name: str) -> NodeGroupState:
        pass
    
    @abstractmethod
    async def update_node_group(self, cluster_name: str, node_group_name: str, config: NodeGroupConfiguration) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    async def delete_node_group(self, cluster_name: str, node_group_name: str) -> bool:
        pass
    
    @abstractmethod
    async def get_kubeconfig(self, cluster_name: str) -> str:
        pass
    
    @abstractmethod
    async def list_clusters(self) -> List[Dict[str, Any]]:
        pass
    
    @abstractmethod
    async def get_available_instance_types(self) -> List[str]:
        pass
    
    @abstractmethod
    async def get_available_kubernetes_versions(self) -> List[str]:
        pass
    
    @abstractmethod
    def map_instance_type(self, generic_type: str) -> str:
        pass

    async def pre_deployment_validation(self, config: KubernetesClusterConfiguration) -> List[str]:
        return []
    
    async def post_deployment_validation(self, cluster_name: str, config: KubernetesClusterConfiguration) -> None:
        pass
    
    async def get_cluster_info(self, cluster_name: str) -> Dict[str, Any]:
        return {}
    
    async def backup_cluster(self, cluster_name: str) -> str:
        raise NotImplementedError("Backup not supported")
    
    async def restore_cluster(self, backup_id: str, cluster_name: str) -> bool:
        raise NotImplementedError("Restore not supported")
