#!/usr/bin/env python

from subprocess import Popen,PIPE
from cloud import logger
from cloud import config
import json
import uuid
import os
import re

log = logger.getLogger()

monaddr_template = """<host name='%(mon_ip)s' port='%(mon_port)s'/>"""
volume_template = """
<disk type='network' device='disk'>
<driver name='qemu' type='raw' cache='writeback'/>
<auth username='{0}'>
<secret type='ceph' uuid='{1}'/>
</auth>
<source protocol='rbd' name='{2}/{3}'>
{4}
</source>
<target dev='TARGET' bus='virtio'/>
</disk>
"""

cdrom_template = """
<disk type='network' device='cdrom'>
<driver name='qemu' type='raw'/>
<auth username='{0}'>
<secret type='ceph' uuid='{1}'/>
</auth>
<source protocol='rbd' name='{2}/{3}'>
{4}
</source>
<backingStore/>
<target dev='{5}' bus='ide'/>
<readonly/>
</disk>
"""

cdrom_null = """
<disk type='file' device='cdrom'>
<driver name='qemu' type='raw'/>
<backingStore/>
<target dev='{0}' bus='ide'/>
<readonly/>
</disk>
"""

def domain_stat(domain):
    virshcmd = "virsh dominfo %s" % domain
    dominfo = Popen(virshcmd,
                    shell=True,
                    stdout=PIPE).stdout.readlines()
    stateinfo = [ line for line in dominfo if "State" in line ]
    stat = stateinfo[0].split(":")[1].strip()
    return stat

def cdrom_in_first_order(domain):
    virshcmd = "virsh dumpxml %s" % domain
    virshxml = Popen(virshcmd,
                     shell=True,
                     stdout=PIPE).stdout.readlines()
    hd_index = -1
    cdrom_index = -1
    for linu, rec in enumerate(virshxml):
        if hd_index > 0 and cdrom_index > 0:
            break
        elif "dev='hd'" in rec:
            hd_index = linu
        elif "dev='cdrom'" in rec:
            cdrom_index = linu
    
    return cdrom_index < hd_index

def persist(content, target):
    if len(content.strip()):
        if len(target) and target.count("/") > 0:
            parent, dst = target.rsplit("/", 1)
            if not os.path.exists(parent):
                os.makedirs(parent)
                mode = "a"
            elif os.path.exists(target):
                mode = "w"
            else:
                mode = "a"
            writer = open(target, mode)
            writer.write(content)
            writer.close()


def reset_cdrom_index(domain, cdrom_order):
    cdrom_first = cdrom_in_first_order(domain)
    if cdrom_first and cdrom_order == 0:
        return True
    
    if not cdrom_first and cdrom_order > 0:
        return True

    domain_qemu_xml = "%s%s.xml" % (config.qemu_hosts, domain)
    if not os.path.exists(domain_qemu_xml):
        log.warn("Qemu XML for domain %s not found !" % domain)
        return False
    work_dir = "/tmp/"
    backup_prefix = "backup-"
    reset_prefix = "tmp-"
 
    backup_target = "%s%s%s.xml" % (work_dir, backup_prefix, domain)
    if os.path.exists(backup_target):
        os.remove(backup_target)
    hot_xml = open(domain_qemu_xml).read()
    open(backup_target, "a").write("%s" % hot_xml)
    
    tmp, _ = re.subn("dev='cdrom'", "dev='tmp'", hot_xml)
    tmp, _ = re.subn("dev='hd'", "dev='cdrom'", tmp)
    tmp, _ = re.subn("dev='tmp'", "dev='hd'", tmp)
    xml_post_reset = "%s%s%s.xml" % (work_dir, reset_prefix, domain) 
    persist(tmp, xml_post_reset)

    def stop():
        stop_info = Popen("virsh destroy %s" % domain,
                          shell=True,
                          stdout=PIPE).stdout.read()
        log.info("Stop domain %s while resetting boot order: %s" % (domain, stop_info))

    def start():
        start_info = Popen("virsh start %s" % domain,
                           shell=True,
                           stdout=PIPE).stdout.read()
        log.info("Start domain %s while resetting boot order: %s" % (domain, start_info))

    def undefine():
        info = Popen("virsh undefine %s" % domain,
                     shell=True,
                     stdout=PIPE).stdout.read()
        log.info("Undefine domain %s while resetting boot order: %s" % (domain, info))

    def redefine():
        info = Popen("virsh define %s" % xml_post_reset,
                     shell=True,
                     stdout=PIPE).stdout.read()
        log.info("Define domain %s from file %s: %s" % (domain, xml_post_reset, info))

    current_state = domain_stat(domain)
    if "shut off" not in current_state:
        stop()

    undefine()
    redefine()

    if "shut off" not in current_state:
        start()

    return True

def ceph_pool_exists(pool):
    cephcmd = "ceph osd pool ls"
    pipe = Popen(cephcmd,
                 shell=True,
                 stdout=PIPE,
                 stderr=PIPE)
    output = pipe.stdout.read()
    errinfo = pipe.stderr.read()
    log.debug("Check ceph pool:output: \n%s" % output)
    log.debug("Check ceph pool:errinfo: \n%s" % errinfo)
    if not errinfo:
        return pool in output
    else:
        log.warn("Ceph Authentication not ready: %s" % errinfo)
        return False

def ceph_blk_exists(pool, blk, auth_user):
    if not ceph_pool_exists(pool):
        return False
    rbdcmd = "rbd info %s/%s --name client.%s" % (pool, blk, auth_user)
    pipe = Popen(rbdcmd,
                 shell=True,
                 stdout=PIPE,
                 stderr=PIPE)
    err = pipe.stderr.read()
    info = pipe.stdout.read()
    log.debug("Check if file %s in pool %s: %s %s" % (blk, pool, err, info))

    if err and "No such file" in err:
        log.warn("Check file %s in ceph pool %s: %s" % (blk, pool, err))
        return False
    return True

def collect_monaddrs():
    mons = []
    cephcmd = "ceph mon dump --format=json"
    result = Popen(cephcmd, shell=True, stdout=PIPE).stdout.read()
    lines = result.split("\n")
    if lines[0].startswith("dumped monmap epoch"):
        lines = lines[1:]
    monmap = json.loads("\n".join(lines))
    addrs = [mon["addr"] for mon in monmap["mons"]]
    for addr in addrs:
        temp = addr.split("/")[0]
        ip, port = temp.split(":")
        mons.append({"mon_ip": ip,"mon_port": port})
    return mons 

def generate_monsxml():
    mons = collect_monaddrs()
    monsXML = ""
    for mon in mons:
        monsXML = "%s%s" % (monsXML, monaddr_template % mon)
    return monsXML    

def assemble_volume_xml(pool, name):
    monsXML = generate_monsxml()
    result = volume_template.format(config.ceph_user,
                                    config.ceph_secret_uuid,
                                    pool,
                                    name,
                                    monsXML)
    return result

def assemble_cdrom_xml(file_from_which_pool, cdrom_file):
    if not (file_from_which_pool or cdrom_file):
        return cdrom_null.format(config.default_cdrom_target)
    monsXML = generate_monsxml()
    result = cdrom_template.format(config.ceph_iso_pool_user,
                                   config.ceph_iso_secret_uuid,
                                   file_from_which_pool,
                                   cdrom_file,
                                   monsXML,
                                   config.default_cdrom_target)
    return result

def domain_exists(domain):
    virshcmd = "virsh list --name --all"
    domains = Popen(virshcmd, shell=True, stdout=PIPE).stdout.read()
    return domains.count(domain) > 0

def get_available_blk_target(domain):
    if domain_exists(domain):
        virshcmd = "virsh domblklist %s" % domain
        blks = Popen(virshcmd,
                     shell=True,
                     stdout=PIPE).stdout.readlines()
        blks = blks[2:-1]
        targets = []
        for blk in blks:
            if blk.startswith("vd"):
                targets.append(blk.split()[0].strip())
        for w in xrange(97, 123):
            target = "vd%s" % chr(w)
            if target not in targets:
                return target
        

def device_exists(device):
    linkcmd = "ip link show %s" % device
    result = Popen(linkcmd, shell=True, stderr=PIPE).stderr.read()
    return not result

def device_up(device):
    if device_exists(device):
        linkup = "ip link set %s up" % device
        result = Popen(linkup, shell=True, stderr=PIPE).stderr.read()
        if not result:
            return True
        log.warn("Cannt set %s up" % device)
        return False
    else:
        log.warn("Device %s not found" % device)
        return False

def command_supported(command):
    test = "%s --help" % command
    stderr = Popen(test, shell=True, stderr=PIPE).stderr.read()
    log.debug(stderr)
    return not stderr

def ovscmd_supported():
    return command_supported("ovs-vsctl")

def brcmd_supported():
    return command_supported("brctl")

def bridge_exists(bridge):
    brcmd = "brctl show %s" % bridge
    result = Popen(brcmd, shell=True, stderr=PIPE).stderr.read()
    return not result

def setup_bridge(bridge):
    if bridge_exists(bridge):
        device_up(bridge)  

def add_bridge(bridge):
    if bridge_exists(bridge):
        return True
    brcmd = "brctl addbr %s" % bridge
    errinfo = Popen(brcmd,
                    shell=True,
                    stderr=PIPE).stderr.read()
    if errinfo:
        log.warn("Bridge error: %s" % errinfo)
        return False
    return True
     
def ovswitch_exists(ovswitch):
    if not ovscmd_supported():
        log.warn("Openvswitch components not ready !")
        return False
    ovscmd = "ovs-vsctl list-br"
    ovswitchs = Popen(ovscmd, shell=True, stdout=PIPE).stdout.read()
    return ovswitch in ovswitchs

def __bridge_has_interface(bridge, interface):
    if not (device_exists(interface) and device_exists(bridge)):
        log.debug("Bridge %s or device %s not ready yet" % (bridge, interface))
        return False
    def __collect_devices(brg):
        brcmd = "brctl show %s" % brg
        brginfo = Popen(brcmd,
                        shell=True,
                        stdout=PIPE).stdout.read()
        brginfo = [ rec for rec in brginfo.split("\n")[1:] if len(rec.strip()) > 0 ]
        devices = [] 
        dev = brginfo[0].split()
	if len(dev) == 4:
            devices.append(dev[3].strip())
            if len(brginfo) > 1:
                for line in brginfo[1:]:
                    devices.append(line.strip())
        return devices

    devices = __collect_devices(bridge)
    return interface in devices

def connect_ovs_to_bridge(ovs, ovs_device, bridge):
    if not (ovscmd_supported() and brcmd_supported()):
        log.warn("Ovs components or bridge-utils required !")
        return False

    if not (ovswitch_exists(ovs) and bridge_exists(bridge)):
        log.warn("Cannt connect %s to %s: either of them not found !" % (ovs, bridge))
        return False
    ovscmd_addport = """
                     ovs-vsctl -- --if-exists del-port %(port)s \
                               -- add-port %(ovs)s %(port)s \
                               -- set Interface %(port)s type=internal \
                               -- set Interface %(port)s external-ids:iface-status=active \
                               -- set Interface %(port)s external-ids:iface-id=%(uuid)s
                     """ % {"ovs": ovs, "port": ovs_device, "uuid": uuid.uuid4()}
    errinfo = Popen(ovscmd_addport,
                    shell=True,
                    stderr=PIPE).stderr.read()
    if errinfo:
        log.warn("Openvswitch error: %s" % errinfo)
        return False

    device_up(ovs_device)
    device_up(bridge)

    if __bridge_has_interface(bridge, ovs_device):
        return True
    
    brcmd = "brctl addif %s %s" % (bridge, ovs_device)
    errinfo = Popen(brcmd,
                    shell=True,
                    stderr=PIPE).stderr.read()
    if errinfo:
        log.warn("Bridge error: %s" % errinfo)
    return True
