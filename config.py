#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author  guojy8993
# Date    2016/12/29

######################################## [Log] ###########################################
# Logging Basic instance related operations
log_path = "/var/log/cloud.log"
# Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL
log_level = "DEBUG"

######################################## [Base] ##########################################
# Directory storing functional scripts
local_ip = "10.112.1.4"
scripts_dir = "/opt/scripts/"
instance_scripts = "%s%s" % (scripts_dir, "instance")
volume_scripts = "%s%s" % (scripts_dir, "disk")
network_scripts = "%s%s" % (scripts_dir, "network")


######################################## [Instance] #######################################
# Doamin running vnc token generation service and NOVNC service
vnc_host = "10.160.0.128"
# Port listened by vnc token generation service
vnc_gentoken_service_port = 9000
# Vnc token generation service url
vnc_gentoken_endpoint = "http://%s:%d/" % (vnc_host, vnc_gentoken_service_port)
# Port listented by novnc service(websockify), default 6080
vnc_proxy_port = 6080
# Vnc url prefix with token to be filled in
vnc_url_template = "http://%s:%d/vnc_auto.html?token=" % (vnc_host, vnc_proxy_port)
# Base Directory Storing configuration XMLs
instance_data = "/etc/libvirt/qemu/"
# initial instance template
instance_template_name = "instance_template.xml"

# Clock offset option in virshxml
clock_offset_linux = "utc"
clock_offset_windows = "localtime"
default_cdrom_target = "hda"
qemu_hosts = "/etc/libvirt/qemu/"

######################################## [Image] ##########################################
ceph_config = "/etc/ceph/ceph.conf"
ceph_user = "cinder"
ceph_secret_uuid = "6a085c23-2177-242d-7661-c785df7f6239"
ceph_image_pool = "images"

ceph_iso_pool = "tinyiso"
ceph_iso_pool_user = "tinyiso"
ceph_iso_secret_uuid = "bd25d4ac-f47a-430e-a032-1fc20fbf12a8"


######################################## [Network] ##########################################
ext_bridge_prefix = "br0"
int_bridge_prefix = "br1"
bridge_name_format = "%(bridge_prefix)s%(domain)s"
ovs_wan_port_prefix = "wan"
ovs_lan_port_prefix = "lan"
ovs_port_format = "%(ovs_port_prefix)s%(domain)s"

######################################## [Volume] ##########################################
volume_name_format = "volume-%(domain)s-%(type)s-%(uuid)s"
volume_type_boot = "system"
volume_type_data = "data"
ceph_volume_pool = "volumes"

######################################## [Cloudinit] #######################################
# Directory that stores temporary
# config drive files of domains
config_drives = "/tmp/config_drives/"
config_drive_iso = "/tmp/isos/"

# By default, in case of any leak of guest domain private information,
# config drive files(folder/iso) are removed no matter whether or not 
# config drive is generated and uploaded.
# However ,for debug purpose, it can be set to False to help figure out
# where possible problem exists
delete_on_config_drive_fail = False

# Different distributions has their NIC configurations
# in different path
NETWORK_CONF_PREFIX = {
    "RH": "/etc/sysconfig/network-scripts/ifcfg-"
}

# Define in which that domain receives its
# network configurations
DOMAIN_IFCFG_BOOTPROTO = "static"

# Define domain MTU value
DOMAIN_IFCFG_MTU = 1500
DOMAIN_FQDN = ".cloud.org"

