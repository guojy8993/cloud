#!/usr/bin/env python

from cloud.service.network import Network
from cloud import logger

log = logger.getLogger()
net_service = Network()

def test_build_network_links(domain):
    return net_service.build_network_links(domain)    
print test_build_network_links("guojingyu")
