#!/usr/bin/env python3

from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict, validator
from enum import Enum

KUBERNETES_VERSION = '1.34'

class CloudProvider(str, Enum):
    AWS = "aws"

class ClusterState(str, Enum):
    CREATING = "creating"
    ACTIVE = "active" 
    UPDATING = "updating"
    DELETING = "deleting"
    DELETED = "deleted"
    ERROR = "error"

class NodeGroupState(str, Enum):
    CREATING = "creating"
    ACTIVE = "active"
    UPDATING = "updating"
    DELETING = "deleting"
    DELETED = "deleted"
    ERROR = "error"

class InstanceType(str, Enum):
    T3_MICRO = "t3_micro"
    T3_SMALL = "t3_small"
    T3_MEDIUM = "t3_medium"
    T3_LARGE = "t3_large"
    M5_LARGE = "m5_large"
    M5_XLARGE = "m5_xlarge"
    R5_LARGE = "r5_large"

class CloudCredentials(BaseModel):
    model_config = ConfigDict(extra='forbid')
    
    provider: CloudProvider
    region: str = Field(...)
    credentials: Dict[str, Any] = Field(default_factory=dict)

class AWSCredentials(CloudCredentials):
    provider: CloudProvider = Field(default=CloudProvider.AWS, frozen=True)
    access_key_id: Optional[str] = Field(default=None)
    secret_access_key: Optional[str] = Field(default=None)
    session_token: Optional[str] = Field(default=None)
    profile: Optional[str] = Field(default=None)

class NetworkConfiguration(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    vpc_cidr: str = Field(default="10.0.0.0/16")
    public_subnets: List[str] = Field(default_factory=lambda: ["10.0.1.0/24", "10.0.2.0/24"])
    private_subnets: List[str] = Field(default_factory=lambda: ["10.0.10.0/24", "10.0.20.0/24"])
    enable_nat_gateway: bool = Field(default=True)
    dns_enabled: bool = Field(default=True)
    
    @validator('public_subnets', 'private_subnets')
    def validate_subnets(cls, v):
        if len(v) < 2:
            raise ValueError("At least 2 subnets required for high availability")
        return v

class StorageConfiguration(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    storage_class: str = Field(default="gp3")
    size: str = Field(default="10Gi")
    iops: Optional[int] = Field(default=3000)
    throughput: Optional[int] = Field(default=125)
    encrypted: bool = Field(default=True)
    backup_retention_days: int = Field(default=7)

class SecurityConfiguration(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    enable_pod_security_policy: bool = Field(default=True)
    enable_network_policy: bool = Field(default=True)
    enable_rbac: bool = Field(default=True)
    enable_encryption_at_rest: bool = Field(default=True)
    enable_encryption_in_transit: bool = Field(default=True)
    allowed_cidr_blocks: List[str] = Field(default_factory=lambda: ["0.0.0.0/0"])
    enable_private_endpoint: bool = Field(default=False)

class NodeGroupConfiguration(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    name: str = Field(...)
    instance_types: List[Union[InstanceType, str]] = Field(default=[InstanceType.T3_SMALL])
    min_size: int = Field(default=1)
    max_size: int = Field(default=10)
    desired_size: int = Field(default=2)
    disk_size: int = Field(default=50)
    ami_type: str = Field(default="BOTTLEROCKET_x86_64")
    spot_instances: bool = Field(default=False)
    auto_scaling_enabled: bool = Field(default=True)
    labels: Dict[str, str] = Field(default_factory=dict)
    taints: List[Dict[str, str]] = Field(default_factory=list)
    
    @validator('desired_size')
    def validate_desired_size(cls, v, values):
        min_size = values.get('min_size', 1)
        max_size = values.get('max_size', 10)
        if not (min_size <= v <= max_size):
            raise ValueError(f"desired_size must be between min_size ({min_size}) and max_size ({max_size})")
        return v

class KubernetesClusterConfiguration(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    name: str = Field(...)
    version: str = Field(default=KUBERNETES_VERSION)
    node_groups: List[NodeGroupConfiguration] = Field(...)
    network: NetworkConfiguration = Field(default_factory=NetworkConfiguration)
    storage: StorageConfiguration = Field(default_factory=StorageConfiguration)
    security: SecurityConfiguration = Field(default_factory=SecurityConfiguration)
    enable_logging: bool = Field(default=True)
    log_types: List[str] = Field(default_factory=lambda: ["api", "audit", "authenticator"])
    enable_monitoring: bool = Field(default=True)
    enable_autoscaling: bool = Field(default=True)
    provider_config: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('node_groups')
    def validate_node_groups(cls, v):
        if not v:
            raise ValueError("At least one node group is required")
        return v

class DeploymentResult(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    success: bool = Field(...)
    cluster_id: Optional[str] = Field(default=None)
    cluster_arn: Optional[str] = Field(default=None)
    cluster_endpoint: Optional[str] = Field(default=None)
    cluster_state: Optional[ClusterState] = Field(default=None)
    
    kubeconfig: Optional[str] = Field(default=None)
    
    vpc_id: Optional[str] = Field(default=None)
    subnet_ids: List[str] = Field(default_factory=list)
    
    node_groups: List[Dict[str, Any]] = Field(default_factory=list)
    
    created_at: Optional[datetime] = Field(default=None)
    updated_at: Optional[datetime] = Field(default=None)
    
    error_message: Optional[str] = Field(default=None)
    error_code: Optional[str] = Field(default=None)
    
    metadata: Dict[str, Any] = Field(default_factory=dict)

class QdrantConfiguration(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    namespace: str = Field(default="qdrant-system")
    replicas: int = Field(default=2)
    image: str = Field(default="qdrant/qdrant:v1.8.1")
    resources: Dict[str, Dict[str, str]] = Field(
        default_factory=lambda: {
            "requests": {"memory": "1Gi", "cpu": "500m"},
            "limits": {"memory": "2Gi", "cpu": "1000m"}
        }
    )
    storage_size: str = Field(default="10Gi")
    storage_class: str = Field(default="gp3")
    service_type: str = Field(default="LoadBalancer")
    http_port: int = Field(default=6333)
    grpc_port: int = Field(default=6334)
    enable_authentication: bool = Field(default=True)
    enable_jwt_rbac: bool = Field(default=True)
    enable_cluster_mode: bool = Field(default=True)
    p2p_port: int = Field(default=6335)

class DeploymentConfiguration(BaseModel):
    model_config = ConfigDict(extra='allow')
    
    provider: CloudProvider = Field(default=CloudProvider.AWS)
    credentials: AWSCredentials = Field(...)
    cluster: KubernetesClusterConfiguration = Field(...)
    qdrant: QdrantConfiguration = Field(default_factory=QdrantConfiguration)
    tags: Dict[str, str] = Field(default_factory=dict)
    dry_run: bool = Field(default=False)
    
    @validator('credentials')
    def validate_credentials(cls, v, values):
        provider = values.get('provider', CloudProvider.AWS)
        if provider == CloudProvider.AWS and not isinstance(v, AWSCredentials):
            raise ValueError("AWSCredentials required for AWS provider")
        return v
