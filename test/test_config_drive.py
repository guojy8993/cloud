#!/usr/bin/env python
# -*- coding:utf-8 -*-

from cloud.cloudinit import config_drive

def test_create_config_drive_tree(domain):
    config_drive.create_config_drive_tree(domain)
# test_create_config_drive_tree("test")

def test_mkisofs(tree, domain):
    config_drive.mkisofs(tree, domain)
# test_mkisofs("/tmp/config_drives/test", "/root/configdrive.iso")

def test_randstr(length):
    print config_drive.randstr(length)

# test_randstr(20)

def test_encode(s):
    return config_drive.encode(s)

def test_decode(s):
    return config_drive.decode(s)

# encode = test_encode("administrator123456789#$%^&*")
encode = test_encode("openstack")
print encode
print test_decode(encode)



"""
if __name__ == "__main__":
    domain = "gateway"
    adminPass = "admin"
    domain_id = None
    hostname = "gw.cloud.org"
    hosts = None
    networks = {
        "eth0": {
            "ip": "122.111.126.1",
            "prefix": "24",
            "gateway": "122.111.126.1",
            "dns1": "8.8.8.8",
            "dns2": "8.8.4.4"
        },
        "eth1": {
            "ip": "10.100.0.1",
            "prefix": "16",
            "gateway": "10.100.0.1"
        }
    }
    configdrive = config_drive.ConfigDrive(domain,
                                           adminPass,
                                           hostname,
                                           networks,
                                           domain_id,
                                           hosts)
    print configdrive.geniso()
    print configdrive.upload() 
"""
