#!/usr/bin/env python3

import logging
from typing import Union

from .models import CloudProvider
from .models import AWSCredentials, CloudCredentials
from .interface import CloudProviderInterface
from .aws_provider import AWSProvider

logger = logging.getLogger(__name__)

class CloudProviderFactory:
    _providers = {
        CloudProvider.AWS: AWSProvider,
    }
    
    @classmethod
    def create_provider(cls, credentials: Union[AWSCredentials, CloudCredentials]) -> CloudProviderInterface:
        if isinstance(credentials, AWSCredentials):
            provider_type = CloudProvider.AWS
        else:
            provider_type = credentials.provider
        
        if provider_type not in cls._providers:
            supported = list(cls._providers.keys())
            raise ValueError(f"Unsupported provider: {provider_type}. Supported: {supported}")
        
        provider_class = cls._providers[provider_type]
        
        try:
            provider = provider_class(credentials)
            logger.info(f"Created {provider_type.value} provider for {credentials.region}")
            return provider
        except Exception as e:
            logger.error(f"Failed to create {provider_type.value} provider: {e}")
            raise
    
    @classmethod
    def get_supported_providers(cls) -> list[CloudProvider]:
        return list(cls._providers.keys())
    
    @classmethod
    def is_provider_supported(cls, provider: CloudProvider) -> bool:
        return provider in cls._providers

def create_provider(credentials: Union[AWSCredentials, CloudCredentials]) -> CloudProviderInterface:
    return CloudProviderFactory.create_provider(credentials)
