#!/usr/bin/env python3

import asyncio
import logging
import subprocess
from typing import Dict, List, Optional, Any
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

from .interface import CloudProviderInterface
from .models import (
    AWSCredentials,
    CloudProvider,
    KubernetesClusterConfiguration,
    NodeGroupConfiguration,
    DeploymentResult,
    ClusterState,
    NodeGroupState,
    InstanceType,
    KUBERNETES_VERSION
)

logger = logging.getLogger(__name__)

class AWSProvider(CloudProviderInterface):
    DEFAULT_EKS_VERSION = KUBERNETES_VERSION
    
    INSTANCE_TYPE_MAPPING = {
        InstanceType.T3_MICRO.value: "t3.micro",
        InstanceType.T3_SMALL.value: "t3.small",
        InstanceType.T3_MEDIUM.value: "t3.medium",
        InstanceType.T3_LARGE.value: "t3.large"
    }
    def __init__(self, credentials: AWSCredentials):
        super().__init__(credentials)
        self.aws_credentials = credentials
        self._eks_provisioner = None
    
    @property
    def provider_type(self) -> CloudProvider:
        return CloudProvider.AWS
    
    @property
    def eks_provisioner(self):
        if self._eks_provisioner is None:
            from ..eks_provisioner import EKSProvisioner
            self._eks_provisioner = EKSProvisioner(
                region=self.region,
                profile=self.aws_credentials.profile
            )
        return self._eks_provisioner
    
    async def validate_credentials(self) -> bool:
        try:
            if self.aws_credentials.profile:
                session = boto3.Session(profile_name=self.aws_credentials.profile)
            else:
                session = boto3.Session(
                    aws_access_key_id=self.aws_credentials.access_key_id,
                    aws_secret_access_key=self.aws_credentials.secret_access_key,
                    aws_session_token=self.aws_credentials.session_token
                )
            
            sts_client = session.client('sts', region_name=self.region)
            sts_client.get_caller_identity()
            
            logger.info("AWS credentials validated successfully")
            return True
            
        except ClientError as e:
            logger.error(f"AWS credential validation failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error validating AWS credentials: {e}")
            return False
    
    async def create_cluster(self, config: KubernetesClusterConfiguration) -> DeploymentResult:
        try:
            logger.info(f"Creating EKS cluster: {config.name}")
            
            result = self.eks_provisioner.provision_cluster(config)

            await self._install_ebs_csi_driver(config.name)
            
            deployment_result = DeploymentResult(
                success=True,
                cluster_id=config.name,
                cluster_arn=result.get('cluster_arn'),
                cluster_endpoint=None,
                cluster_state=ClusterState.ACTIVE,
                kubeconfig=None,
                vpc_id=None,
                subnet_ids=[],
                node_groups=result.get('nodegroup_arns', []),
                created_at=datetime.now(),
                metadata=result
            )
            
            logger.info(f"EKS cluster {config.name} created successfully")
            return deployment_result
            
        except Exception as e:
            logger.error(f"Failed to create EKS cluster {config.name}: {e}")
            return DeploymentResult(
                success=False,
                error_message=str(e),
                error_code="CLUSTER_CREATION_FAILED"
            )
    
    async def get_cluster_status(self, cluster_name: str) -> ClusterState:
        try:
            if self.aws_credentials.profile:
                session = boto3.Session(profile_name=self.aws_credentials.profile)
            else:
                session = boto3.Session(
                    aws_access_key_id=self.aws_credentials.access_key_id,
                    aws_secret_access_key=self.aws_credentials.secret_access_key,
                    aws_session_token=self.aws_credentials.session_token
                )
            
            eks_client = session.client('eks', region_name=self.region)
            response = eks_client.describe_cluster(name=cluster_name)
            status = response['cluster']['status']
            
            status_mapping = {
                'CREATING': ClusterState.CREATING,
                'ACTIVE': ClusterState.ACTIVE,
                'UPDATING': ClusterState.UPDATING,
                'DELETING': ClusterState.DELETING,
                'FAILED': ClusterState.ERROR
            }
            
            return status_mapping.get(status, ClusterState.ERROR)
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return ClusterState.DELETED
            logger.error(f"Failed to get cluster status: {e}")
            return ClusterState.ERROR
        except Exception as e:
            logger.error(f"Unexpected error getting cluster status: {e}")
            return ClusterState.ERROR
    
    async def delete_cluster(self, cluster_name: str, force: bool = False) -> bool:
        try:
            logger.info(f"Deleting EKS cluster: {cluster_name}")
            self.eks_provisioner.delete_cluster(cluster_name)
            return True
        except Exception as e:
            logger.error(f"Failed to delete EKS cluster {cluster_name}: {e}")
            return False
    
    async def get_kubeconfig(self, cluster_name: str) -> str:
        try:
            cmd = [
                "aws", "eks", "update-kubeconfig",
                "--region", self.region,
                "--name", cluster_name,
                "--dry-run"
            ]
            
            if self.aws_credentials.profile:
                cmd.extend(["--profile", self.aws_credentials.profile])
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get kubeconfig for {cluster_name}: {e}")
            raise Exception(f"Failed to generate kubeconfig: {e}")
    
    def map_instance_type(self, generic_type: str) -> str:
        return self.INSTANCE_TYPE_MAPPING.get(generic_type, generic_type)
    
    async def update_cluster(self, cluster_name: str, config: KubernetesClusterConfiguration) -> DeploymentResult:
        return DeploymentResult(
            success=False,
            error_message="Cluster update not implemented yet",
            error_code="NOT_IMPLEMENTED"
        )
    
    async def create_node_group(self, cluster_name: str, config: NodeGroupConfiguration) -> Dict[str, Any]:
        return {"node_group_name": config.name, "status": "creating"}
    
    async def get_node_group_status(self, cluster_name: str, node_group_name: str) -> NodeGroupState:
        return NodeGroupState.ACTIVE
    
    async def update_node_group(self, cluster_name: str, node_group_name: str, config: NodeGroupConfiguration) -> Dict[str, Any]:
        return {"status": "updated"}
    
    async def delete_node_group(self, cluster_name: str, node_group_name: str) -> bool:
        return True
    
    async def list_clusters(self) -> List[Dict[str, Any]]:
        try:
            if self.aws_credentials.profile:
                session = boto3.Session(profile_name=self.aws_credentials.profile)
            else:
                session = boto3.Session(
                    aws_access_key_id=self.aws_credentials.access_key_id,
                    aws_secret_access_key=self.aws_credentials.secret_access_key,
                    aws_session_token=self.aws_credentials.session_token
                )
            
            eks_client = session.client('eks', region_name=self.region)
            response = eks_client.list_clusters()
            
            clusters = []
            for cluster_name in response['clusters']:
                cluster_info = eks_client.describe_cluster(name=cluster_name)
                clusters.append({
                    'name': cluster_name,
                    'status': cluster_info['cluster']['status'],
                    'version': cluster_info['cluster']['version'],
                    'endpoint': cluster_info['cluster']['endpoint'],
                    'created_at': cluster_info['cluster']['createdAt']
                })
            
            return clusters
            
        except Exception as e:
            logger.error(f"Failed to list clusters: {e}")
            return []
    
    async def get_available_instance_types(self) -> List[str]:
        return list(self.INSTANCE_TYPE_MAPPING.values())
    
    async def get_available_kubernetes_versions(self) -> List[str]:
        return [self.DEFAULT_EKS_VERSION]
    
    async def _install_ebs_csi_driver(self, cluster_name: str) -> bool:
        logger.info("Installing AWS EBS CSI Driver addon...")
        
        try:
            if self.aws_credentials.profile:
                session = boto3.Session(profile_name=self.aws_credentials.profile)
            else:
                session = boto3.Session(
                    aws_access_key_id=self.aws_credentials.access_key_id,
                    aws_secret_access_key=self.aws_credentials.secret_access_key,
                    aws_session_token=self.aws_credentials.session_token
                )
            
            eks_client = session.client('eks', region_name=self.region)
            
            # Check if addon already exists
            try:
                eks_client.describe_addon(
                    clusterName=cluster_name,
                    addonName="aws-ebs-csi-driver"
                )
                logger.info("EBS CSI Driver addon already exists")
                return True
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    raise e
                pass

            eks_client.create_addon(
                clusterName=cluster_name,
                addonName="aws-ebs-csi-driver"
            )
            logger.info("EBS CSI Driver addon installed successfully")
            return True
        except ClientError as e:
            logger.error(f"Failed to install EBS CSI Driver: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error installing EBS CSI Driver: {e}")
            return False
