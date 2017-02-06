#!/usr/bin/bash
# -*- coding: utf-8 -*-

from subprocess import PIPE, Popen
from cloud.common import utils
from cloud import logger
from cloud import config
import os
import uuid
import json
import base64
import random


log = logger.getLogger()

char_ranges = {
    0: (65, 90, ),
    1: (97, 122, ),
    2: (49, 57, )
}


def randstr(length):
    result = ""
    for i in range(length):
        cap = random.randint(0, 2)
        start, end = char_ranges[cap]
        result = "%s%s" % (result, chr(random.randint(start, end)))
    return result


def encode(original_pwd):
    # [0-1] + base64?32([a-z][0-9]{5}[0-1] + (base64?32)(admin) + padding)

    def _encode(s, n):
        if n == 1:
            return base64.b64encode(s)
        elif n == 0:
            return base64.b32encode(s)
    inner_encode_type = random.randint(0, 1)
    result = ""
    result = "%s%s" % (result, inner_encode_type)
    inner_encoded_pass = _encode(original_pwd, inner_encode_type)
    lenstr = "%s" % (len(inner_encoded_pass) + 32)
    for i in range(5 - len(lenstr)):
        lenstr = "0%s" % lenstr
    result = "%s%s%s" % (lenstr, result, inner_encoded_pass)
    total_length = random.randint(97, 122)
    paddings = randstr(total_length - 1 - len(result))
    inner_str = "%s%s%s" % (chr(total_length), result, paddings)

    outer_encode_type = random.randint(0, 1)
    return "%s%s" % (outer_encode_type, _encode(inner_str, outer_encode_type))


def decode(encoded_pwd):
    if encoded_pwd and (encoded_pwd.startswith("0") or encoded_pwd.startswith("1")):
        outer_encode_type, outer_encoded = int(encoded_pwd[0]), encoded_pwd[1:]

    def _decode(s, n):
        if n == 1:
            return base64.b64decode(s)
        elif n == 0:
            return base64.b32decode(s)
    inner = _decode(outer_encoded, outer_encode_type)
    inner_ecoded_str_length = int(inner[1:6]) - 32

    inner_ecoded_type = int(inner[6])
    inner_encoded_str = inner[7: 7 + inner_ecoded_str_length]

    return _decode(inner_encoded_str, inner_ecoded_type)


def mkisofs(config_drive_tree, target):

    # e.g: mkisofs -R -V config-2 -o /root/haproxy.iso /tmp/config_drives/demo
    # (1) option '-v' specifies the disk label to be
    #                 recognized by domain cloudinit
    # (2) option '-o' specifies the target config drive to ceate
    if not os.path.exists(config_drive_tree):
        log.warn("Config drive %s not found" % config_drive_tree)
        return False

    if os.sep not in target or target.endswith(os.sep):
        log.warn("Config drive target %s invalid" % target)
        return False
    target_parent = target.rsplit(os.sep, 1)[0]
    if not os.path.exists(target_parent):
        os.makedirs(target_parent)

    mkisofs = "mkisofs -R -V config-2 -o %s %s" % (target, config_drive_tree)
    pipe = Popen(mkisofs,
                 shell=True,
                 stdout=PIPE,
                 stderr=PIPE)
    erro = pipe.stderr.read()
    info = pipe.stdout.read()
    log.debug("Make config drive from %s:\n %s" % (config_drive_tree, erro))
    if erro and "extents written" in erro:
        log.debug("Config drive %s created from %s" % (target,
                                                       config_drive_tree))
        return True
    return False


def create_config_drive_tree(domain):

    # The following diagram shows the standard
    # file tree of ConfigDrive that CloudInit can
    # read and parse:
    #
    # openstack
    # ├- content
    # └- latest
    #     ├── meta_data.json
    #     ├── user_data
    #     └  vendor_data.json
    #
    # (1) content: storing files to be copied to domain from config drive,eg:
    #        nic configurations(ifcfg-eth0), hosts, softwares, etc
    # (2) meta_data.json: storing domain metadata, e.g: hostname, uuid, name
    # (3) user_data: /python/shell/powershell/bat scripts
    # (4) vendor_data.json: default {} is ok
    domain_drive = "%s%s" % (config.config_drives, domain)
    if os.path.exists(domain_drive):
        __import__("shutil").rmtree(domain_drive)
    os.makedirs(domain_drive)

    topdir = "%s%s%s" % (domain_drive, os.sep, "openstack")
    file_store = "%s%s%s" % (topdir, os.sep, "content")
    os.makedirs(file_store)

    conf_store = "%s%s%s" % (topdir, os.sep, "latest")
    os.makedirs(conf_store)
    meta_target = "%s%s%s" % (conf_store, os.sep, "meta_data.json")
    utils.persist("{}", meta_target)
    userd_target = "%s%s%s" % (conf_store, os.sep, "user_data")
    utils.persist("# user data scripts\n", userd_target)

    vendor_target = "%s%s%s" % (conf_store, os.sep, "vendor_data.json")
    utils.persist("{}", vendor_target)
    return domain_drive


class ConfigDrive(object):
    def __init__(self,
                 domain,
                 adminPass,
                 hostname,
                 networks,
                 domain_id=None,
                 hosts=None):
        self.domain = domain
        self.user_data = ""
        self.meta_data = {}
        self.adminPass = adminPass if adminPass else "root"
        self.config_drive_tree = create_config_drive_tree(domain)
        self.config_drive_target = "%s%s.iso" % (config.config_drive_iso, domain)
        self.content_files = {}
        self.update_content_with_networks(networks)
        # Other content updating functions can be defined/added
        # here to implement file copyings
        self.persist_meta_data(hostname, domain, domain_id)
        self.persist_user_data()

    def __num_trans(self, num):
        result = ""
        result_length = 4
        for i in range(0, result_length):
            m = result_length - i - 1
            result = "%s%s" % (result, num / (10**m))
            num = num % (10**m)
        return result

    def assemble_dev_config(self,
                            dev,
                            ip=None,
                            prefix=None,
                            gateway=None,
                            dns1=None,
                            dns2=None):

        template = \
            "TYPE=Ethernet\nBOOTPROTO={0}\nDEVICE={1}\nONBOOT=yes\nMTU={2}\n{3}"
        static_network = "IPADDR={0}\nPREFIX={1}\nGATEWAY={2}\n{3}"

        if config.DOMAIN_IFCFG_BOOTPROTO == "dhcp":
            network_info = ""
        elif config.DOMAIN_IFCFG_BOOTPROTO == "static":
            dns_info = ""
            if dns1:
                dns_info = "%s\nDNS1=%s" % (dns_info, dns1)
            if dns2:
                dns_info = "%s\nDNS2=%s" % (dns_info, dns2)
            network_info = static_network.format(ip or "",
                                                 prefix or "",
                                                 gateway or "",
                                                 dns_info)

        return template.format(config.DOMAIN_IFCFG_BOOTPROTO,
                               dev, config.DOMAIN_IFCFG_MTU,
                               network_info)

    def update_content_with_networks(self, networks):
        # NOTE:
        # Now, config drive content only provides Domain ifcfg-XX file copying
        # In future, hosts/resolve/yum.conf and so on , can be injected
        if not getattr(self, "content_files"):
            self.content_files = []
        for dev, dev_conf in networks.iteritems():
            item = {}
            item["path"] = "%s%s" % (config.NETWORK_CONF_PREFIX["RH"], dev)
            content_index = len(self.content_files)
            item["content_path"] = \
                "/content/%s" % self.__num_trans(content_index)
            self.content_files.append(item)

            dev_conf = self.assemble_dev_config(dev, **dev_conf)
            dev_content_file = "%s%s%s%s" % (self.config_drive_tree,
                                             os.sep, "openstack",
                                             item["content_path"])
            utils.persist(dev_conf, dev_content_file)

        return self.content_files

    def set_admin_pass(self):
        self.user_data = \
            "%s%s" % (self.user_data,
                      "echo \"%s\" | passwd --stdin root\n" % self.adminPass)

    def set_network(self):
        self.user_data = "%s%s" % (self.user_data, "service network restart\n")

    def persist_user_data(self):

        self.user_data = "%s%s" % (self.user_data, "#!/bin/bash\n")
        # NOTE:
        # In user_data script, it's import to arrange
        # specified action around appropriate EVENT .
        # e.g:
        # It's fit that you start your haproxy process after
        # domain network restarted and IPs configured
        self.set_admin_pass()
        self.set_network()
        # e.g: unarchive httpd.tar.gz
        # e.g: install httpd.rpm & dependency packages
        # e.g: copy user website to httpd wwwroot & chmod
        # e.g: start httpd service
        # e.g: set firewall and expose service port
        #
        # In future, 'ACTION GROUPs' will be added and executed in sequence
        # this's very similar to Iptable Chains and Chain rules
        # e.g:
        # Basic_Settings = ('set_adminPass', 'set_hosts',
        #                   'set_hostname', 'set_yum', ...)
        # Rpm_Install  = ('install_httpd', 'install_haproxy', ...)
        # Service_Settings = ('init_mariadb', 'deploy_httpd', ...)
        # Service_Starting = ('start_httpd', 'start_hginx', ...)
        # Expose_Service_Ports = ('enable_http_access',
        #                         'enable_nginx_access', ...)
        #
        # For simplicity, this method only provides functions:
        # (1) set adminPass
        # (2) restart network
        utils.persist("%s" % self.user_data,
                      "%s%s%s%s%s%s%s" % (self.config_drive_tree,
                                          os.sep, "openstack",
                                          os.sep, "latest",
                                          os.sep, "user_data"))

    def persist_meta_data(self, hostname, domain, domain_id):
        self.meta_data["hostname"] = hostname
        self.meta_data["launch_index"] = 0
        self.meta_data["name"] = domain
        self.meta_data["uuid"] = domain_id if domain_id else str(uuid.uuid4())
        self.meta_data["files"] = self.content_files

        utils.persist(json.dumps(self.meta_data),
                      "%s%s%s%s%s%s%s" % (self.config_drive_tree,
                                          os.sep, "openstack",
                                          os.sep, "latest",
                                          os.sep, "meta_data.json"))

    def geniso(self):
        result = mkisofs(self.config_drive_tree, self.config_drive_target)
        if result:
            return self.config_drive_target

    def upload(self):
        remote_target = "%s/%s" % (config.ceph_iso_pool, self.domain)
        # NOTE:
        # Verify if pool/volume already exists
        if utils.ceph_blk_exists(config.ceph_iso_pool,
                                 self.domain,
                                 config.ceph_iso_pool_user):
            log.warn("Config drive %s exists, trying to remove it ..." % remote_target)
            rbdrm = "rbd rm %s --name client.%s" % (remote_target,
                                                    config.ceph_iso_pool_user)

            pipe = Popen(rbdrm, stderr=PIPE, stdout=PIPE, shell=True)
            erro, info = pipe.stderr.read(), pipe.stdout.read()
            log.warn("Config drive removal: %s %s %s" % (rbdrm, erro, info))

        rbdcmd = "rbd import %s %s --name client.%s" % (self.config_drive_target,
                                                        remote_target,
                                                        config.ceph_iso_pool_user)
        pipe = Popen(rbdcmd,
                     shell=True,
                     stderr=PIPE,
                     stdout=PIPE)
        erro = pipe.stderr.read()
        info = pipe.stdout.read()

        os.remove(self.config_drive_target)
        if erro and "done" in erro:
            __import__("shutil").rmtree(self.config_drive_tree)
            return True
        else:
            if config.delete_on_config_drive_fail:
                __import__("shutil").rmtree(self.config_drive_tree)
            log.warn("Upload config drive '%s': %s %s" % (rbdcmd, erro, info))
            return False


class CloudConfig(object):

    def __init__(self):
        pass

    def generate_config_drive(self, **args):
        if "domain" not in args or not args["domain"]:
            return {"code": 1, "message": "Domain name not specified !"}
        domain = args["domain"]

        if "adminPass" not in args or not args["adminPass"]:
            return {"code": 1, "message": "Domain passwd not specified !"}
        adminPass = decode(args["adminPass"])

        if "networks" not in args or not args["networks"]:
            return {"code": 1, "message": "Domain networks not specified !"}
        networks = args["networks"]

        hosts = args.get("hosts", None)
        domain_id = args.get("domain_id", None)
        hostname = args.get("hostname", "%s%s" % (domain, config.DOMAIN_FQDN))

        config_drive = ConfigDrive(domain,
                                   adminPass,
                                   hostname,
                                   networks,
                                   domain_id,
                                   hosts)
        path = config_drive.geniso()
        if not path:
            return {"code": 1, "message": "Domain config drive creating error !"}

        result = config_drive.upload()
        if not result:
            return {"code": 1, "message": "Domain config drive uploading error !"}
        else:
            return {"code": 0, "message": "SUCCESS"}
