#!/usr/bin/env python3

import boto3
import json
import time
import logging
from botocore.exceptions import ClientError, WaiterError
from typing import Dict, List, Optional
from cloud_providers.models import (
    KubernetesClusterConfiguration,
    NodeGroupConfiguration,
    NetworkConfiguration,
    InstanceType,
    KUBERNETES_VERSION
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class EKSProvisioner:
    _cluster_role_name = "qdrant-eks-cluster-role"
    _nodegroup_role_name = "qdrant-eks-nodegroup-role"
    _wait_interval = 3

    def __init__(self, region: str = 'us-west-2', profile: Optional[str] = None):
        self.region = region
        if profile:
            self.session = boto3.Session(profile_name=profile)
        else:
            self.session = boto3.Session()
        
        self.eks_client = self.session.client('eks', region_name=region)
        self.ec2_client = self.session.client('ec2', region_name=region)
        self.iam_client = self.session.client('iam', region_name=region)

    def create_iam_roles(self) -> Dict[str, str]:
        logger.info("Creating IAM roles...")
        
        # EKS Cluster Service Role
        cluster_role_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "eks.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        # EKS Node Group Role
        nodegroup_role_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }

        roles = {}

        while True:
            try:
                role = self.iam_client.get_role(RoleName=EKSProvisioner._cluster_role_name)
                roles['cluster_role_arn'] = role['Role']['Arn']
                break
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    self.iam_client.create_role(
                        RoleName=EKSProvisioner._cluster_role_name,
                        AssumeRolePolicyDocument=json.dumps(cluster_role_doc),
                        Description="IAM role for Qdrant EKS cluster"
                    )
                    self.iam_client.attach_role_policy(
                        RoleName=EKSProvisioner._cluster_role_name,
                        PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
                    )

                    roles['cluster_role_arn'] = f"arn:aws:iam::{self.session.client('sts').get_caller_identity()['Account']}:role/{EKSProvisioner._cluster_role_name}"
                    logger.info(f"Created cluster role: {EKSProvisioner._cluster_role_name}")
                    time.sleep(EKSProvisioner._wait_interval)
                else:
                    raise

        while True:
            try:
                role = self.iam_client.get_role(RoleName=EKSProvisioner._nodegroup_role_name)
                roles['nodegroup_role_arn'] = role['Role']['Arn']
                break
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    self.iam_client.create_role(
                        RoleName=EKSProvisioner._nodegroup_role_name,
                        AssumeRolePolicyDocument=json.dumps(nodegroup_role_doc),
                        Description="IAM role for Qdrant EKS node group"
                    )

                    policies = [
                        "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
                        "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
                        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
                        "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
                    ]

                    for policy in policies:
                        self.iam_client.attach_role_policy(
                            RoleName=EKSProvisioner._nodegroup_role_name,
                            PolicyArn=policy
                        )
                    roles['nodegroup_role_arn'] = f"arn:aws:iam::{self.session.client('sts').get_caller_identity()['Account']}:role/{EKSProvisioner._nodegroup_role_name}"
                    logger.info(f"Created node group role: {EKSProvisioner._nodegroup_role_name}")
                    time.sleep(EKSProvisioner._wait_interval)
                else:
                    raise
        return roles

    def create_vpc_and_subnets(self, network_config: NetworkConfiguration) -> Dict[str, List[str]]:
        logger.info("Creating VPC and subnets...")

        # TODO: this should be wrapped in a "transactional" logic
        # TODO: if tt any point if any resource creation fails this should be rolled back
        try:
            response = self.ec2_client.describe_vpcs(filters=[{"Name": "tag:Name", "Values": ["qdrant-dbaas"]}])
            if len(response["Vpcs"]) > 0:
                raise Exception("VPC already exists")
        except:
            pass

        vpc_response = self.ec2_client.create_vpc(
            CidrBlock=network_config.vpc_cidr,

        )
        vpc_id = vpc_response['Vpc']['VpcId']
        
        # Enable DNS settings after VPC creation
        if network_config.dns_enabled:
            self.ec2_client.modify_vpc_attribute(
                VpcId=vpc_id,
                EnableDnsHostnames={'Value': True}
            )
            self.ec2_client.modify_vpc_attribute(
                VpcId=vpc_id,
                EnableDnsSupport={'Value': True}
            )
        
        # Tag VPC
        self.ec2_client.create_tags(
            Resources=[vpc_id],
            Tags=[
                {'Key': 'Name', 'Value': 'qdrant-dbaas'},
                {'Key': 'Environment', 'Value': 'qdrant-dbaas'}
            ]
        )
        
        # Create Internet Gateway
        igw_response = self.ec2_client.create_internet_gateway()
        igw_id = igw_response['InternetGateway']['InternetGatewayId']
        
        self.ec2_client.attach_internet_gateway(
            InternetGatewayId=igw_id,
            VpcId=vpc_id
        )
        
        # Get availability zones
        azs = self.ec2_client.describe_availability_zones()['AvailabilityZones']
        az_names = [az['ZoneName'] for az in azs[:2]]  # Use first 2 AZs
        
        subnet_ids = {'public': [], 'private': []}
        
        # Create public subnets
        for i, (cidr, az) in enumerate(zip(network_config.public_subnets, az_names)):
            subnet_response = self.ec2_client.create_subnet(
                VpcId=vpc_id,
                CidrBlock=cidr,
                AvailabilityZone=az
            )
            subnet_id = subnet_response['Subnet']['SubnetId']
            
            # Tag subnet
            self.ec2_client.create_tags(
                Resources=[subnet_id],
                Tags=[
                    {'Key': 'Name', 'Value': f'qdrant-public-subnet-{i+1}'},
                    {'Key': 'kubernetes.io/role/elb', 'Value': '1'}
                ]
            )
            
            # Enable auto-assign public IPs
            self.ec2_client.modify_subnet_attribute(
                SubnetId=subnet_id,
                MapPublicIpOnLaunch={'Value': True}
            )
            
            subnet_ids['public'].append(subnet_id)
        
        # Create private subnets
        for i, (cidr, az) in enumerate(zip(network_config.private_subnets, az_names)):
            subnet_response = self.ec2_client.create_subnet(
                VpcId=vpc_id,
                CidrBlock=cidr,
                AvailabilityZone=az
            )
            subnet_id = subnet_response['Subnet']['SubnetId']
            
            # Tag subnet
            self.ec2_client.create_tags(
                Resources=[subnet_id],
                Tags=[
                    {'Key': 'Name', 'Value': f'qdrant-private-subnet-{i+1}'},
                    {'Key': 'kubernetes.io/role/internal-elb', 'Value': '1'}
                ]
            )
            
            subnet_ids['private'].append(subnet_id)
        
        # Create route table for public subnets
        rt_response = self.ec2_client.create_route_table(VpcId=vpc_id)
        rt_id = rt_response['RouteTable']['RouteTableId']
        
        # Add route to internet gateway
        self.ec2_client.create_route(
            RouteTableId=rt_id,
            DestinationCidrBlock='0.0.0.0/0',
            GatewayId=igw_id
        )
        
        # Associate public subnets with route table
        for subnet_id in subnet_ids['public']:
            self.ec2_client.associate_route_table(
                SubnetId=subnet_id,
                RouteTableId=rt_id
            )
        
        # Create NAT Gateway for private subnets internet access
        if subnet_ids['private'] and network_config.enable_nat_gateway:
            logger.info("Creating NAT Gateway for private subnets...")

            eip_response = self.ec2_client.allocate_address(
                Domain='vpc',
                TagSpecifications=[
                    {
                        'ResourceType': 'elastic-ip',
                        'Tags': [
                            {'Key': 'Name', 'Value': 'qdrant-nat-gateway-eip'},
                            {'Key': 'Environment', 'Value': 'qdrant-dbaas'}
                        ]
                    }
                ]
            )
            allocation_id = eip_response['AllocationId']

            nat_response = self.ec2_client.create_nat_gateway(
                SubnetId=subnet_ids['public'][0],
                AllocationId=allocation_id
            )
            nat_gateway_id = nat_response['NatGateway']['NatGatewayId']
            
            self.ec2_client.create_tags(
                Resources=[nat_gateway_id],
                Tags=[
                    {'Key': 'Name', 'Value': 'qdrant-dbaas'},
                    {'Key': 'Environment', 'Value': 'qdrant-dbaas'}
                ]
            )
            
            logger.info("Waiting for NAT Gateway to become available...")
            try:
                waiter = self.ec2_client.get_waiter('nat_gateway_available')
                waiter.wait(NatGatewayIds=[nat_gateway_id])
            except WaiterError as e:
                print(f"Waiter failed: {e}")
                print(f"Last response: {e.last_response}")

            private_rt_response = self.ec2_client.create_route_table(VpcId=vpc_id)
            private_rt_id = private_rt_response['RouteTable']['RouteTableId']

            self.ec2_client.create_route(
                RouteTableId=private_rt_id,
                DestinationCidrBlock='0.0.0.0/0',
                NatGatewayId=nat_gateway_id
            )

            for subnet_id in subnet_ids['private']:
                self.ec2_client.associate_route_table(
                    SubnetId=subnet_id,
                    RouteTableId=private_rt_id
                )
            
            logger.info(f"NAT Gateway {nat_gateway_id} created and configured for private subnets")
        
        logger.info(f"Created VPC {vpc_id} with subnets")
        return subnet_ids

    def create_cluster(self, cluster_name: str, cluster_role_arn: str, subnet_ids: List[str], version: str = KUBERNETES_VERSION) -> str:
        logger.info(f"Creating EKS cluster: {cluster_name}")
        
        try:
            # TODO: set publicAccessCidrs[] to only allowed public IPS.
            # Allow possibility to configure EKS cluster control plane to be accessible only privately for
            # security sensitive workloads
            response = self.eks_client.create_cluster(
                name=cluster_name,
                version=version,
                roleArn=cluster_role_arn,
                resourcesVpcConfig={
                    'subnetIds': subnet_ids,
                    # TODO: Add securityGroupIds
                    'endpointPublicAccess': True,
                    'endpointPrivateAccess': True
                    # 'publicAccessCidrs': []
                },
                logging={
                    'clusterLogging': [
                        {
                            'types': ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'],
                            'enabled': True
                        },
                    ]
                },
                tags={
                    'Environment': 'qdrant-dbaas',
                    'Purpose': 'vector-database'
                }
            )
            
            cluster_arn = response['cluster']['arn']
            logger.info(f"Cluster creation initiated: {cluster_arn}")
            
            # Wait for cluster to be active
            logger.info("Waiting for cluster to become active...")
            try:
                waiter = self.eks_client.get_waiter('cluster_active')
                waiter.wait(
                    name=cluster_name,
                    WaiterConfig={'Delay': 30, 'MaxAttempts': 40}
                )
            except WaiterError as e:
                print(f"Waiter failed: {e}")
                print(f"Last response: {e.last_response}")
            
            logger.info("Cluster is now active")
            return cluster_arn
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceInUseException':
                logger.info("Cluster already exists")
                return self.eks_client.describe_cluster(name=cluster_name)['cluster']['arn']
            else:
                raise e

    def create_node_group(self, cluster_name: str, nodegroup_config: NodeGroupConfiguration, nodegroup_role_arn: str, subnet_ids: List[str]) -> str:
        logger.info(f"Creating node group: {nodegroup_config.name}")
        
        # Convert instance types to AWS format
        from cloud_providers.aws_provider import AWSProvider
        aws_instance_types = []
        for instance_type in nodegroup_config.instance_types:
            if isinstance(instance_type, InstanceType):
                aws_instance_types.append(AWSProvider.INSTANCE_TYPE_MAPPING[instance_type.value])
            else:
                aws_instance_types.append(instance_type)
        
        try:
            response = self.eks_client.create_nodegroup(
                clusterName=cluster_name,
                nodegroupName=nodegroup_config.name,
                scalingConfig={
                    'minSize': nodegroup_config.min_size,
                    'maxSize': nodegroup_config.max_size,
                    'desiredSize': nodegroup_config.desired_size
                },
                diskSize=nodegroup_config.disk_size,
                subnets=subnet_ids,
                instanceTypes=aws_instance_types,
                amiType=nodegroup_config.ami_type,
                nodeRole=nodegroup_role_arn,
                capacityType='SPOT' if nodegroup_config.spot_instances else 'ON_DEMAND',
                tags={
                    'Environment': 'qdrant-dbaas',
                    'Purpose': 'vector-database'
                }
            )
            
            nodegroup_arn = response['nodegroup']['nodegroupArn']
            logger.info(f"Node group creation initiated: {nodegroup_arn}")
            
            # Wait for node group to be active
            logger.info("Waiting for node group to become active...")
            try:
                waiter = self.eks_client.get_waiter('nodegroup_active')
                waiter.wait(
                    clusterName=cluster_name,
                    nodegroupName=nodegroup_config.name,
                    WaiterConfig={'Delay': 30, 'MaxAttempts': 40}
                )
            except WaiterError as e:
                print(f"Waiter failed: {e}")
                print(f"Last response: {e.last_response}")
            
            logger.info("Node group is now active")
            return nodegroup_arn
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceInUseException':
                logger.info("Node group already exists")
                return self.eks_client.describe_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=nodegroup_config.name
                )['nodegroup']['nodegroupArn']
            else:
                raise e

    def provision_cluster(self, config: KubernetesClusterConfiguration) -> Dict[str, str]:
        logger.info("Starting EKS cluster provisioning...")
        
        roles = self.create_iam_roles()
        subnet_info = self.create_vpc_and_subnets(config.network)
        all_subnet_ids = subnet_info['public'] + subnet_info['private']
        
        cluster_arn = self.create_cluster(
            cluster_name=config.name,
            cluster_role_arn=roles['cluster_role_arn'],
            subnet_ids=all_subnet_ids,
            version=config.version
        )
        
        nodegroup_arns = []
        for nodegroup_config in config.node_groups:
            nodegroup_arn = self.create_node_group(
                cluster_name=config.name,
                nodegroup_config=nodegroup_config,
                nodegroup_role_arn=roles['nodegroup_role_arn'],
                subnet_ids=subnet_info['private'] if subnet_info['private'] else all_subnet_ids
            )
            nodegroup_arns.append(nodegroup_arn)
        
        eks_cluster = {
            'cluster_arn': cluster_arn,
            'nodegroup_arns': nodegroup_arns,
            'cluster_name': config.name,
            'region': self.region
        }
        
        logger.info("EKS cluster provisioning completed successfully!")
        return eks_cluster

    def delete_cluster(self, cluster_name: str):
        logger.info(f"Deleting EKS cluster: {cluster_name}")
        
        try:
            # Delete node groups first
            eks_nodegroups = self.eks_client.list_nodegroups(clusterName=cluster_name)['nodegroups']
            for nodegroup in eks_nodegroups:
                logger.info(f"Deleting node group: {nodegroup}")
                self.eks_client.delete_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=nodegroup
                )
                
                # Wait for deletion
                try:
                    waiter = self.eks_client.get_waiter('nodegroup_deleted')
                    waiter.wait(clusterName=cluster_name, nodegroupName=nodegroup)
                except WaiterError as e:
                    print(f"Waiter failed: {e}")
                    print(f"Last response: {e.last_response}")
            # Delete cluster
            self.eks_client.delete_cluster(name=cluster_name)
            
            # Wait for cluster deletion
            try:
                waiter = self.eks_client.get_waiter('cluster_deleted')
                waiter.wait(name=cluster_name)
            except WaiterError as e:
                print(f"Waiter failed: {e}")
                print(f"Last response: {e.last_response}")
            
            logger.info("EKS cluster deleted successfully")
        except ClientError as e:
            logger.error(f"Error deleting cluster: {e}")
            raise e

if __name__ == "__main__":
    # Example usage with Pydantic models
    from cloud_providers.models import (
        KubernetesClusterConfiguration,
        NodeGroupConfiguration,
        NetworkConfiguration,
        InstanceType
    )
    
    # Create example configuration
    cluster_config = KubernetesClusterConfiguration(
        name="test-cluster",
        version=KUBERNETES_VERSION,
        node_groups=[
            NodeGroupConfiguration(
                name="worker-nodes",
                instance_types=[InstanceType.T3_SMALL],
                min_size=1,
                max_size=3,
                desired_size=2
            )
        ]
    )
    
    provisioner = EKSProvisioner(region="us-west-2")
    result = provisioner.provision_cluster(cluster_config)
    print(f"Cluster provisioned successfully: {result}")
