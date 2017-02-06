from cloud.common import utils

def test_check_pool(pool):
    print utils.ceph_pool_exists(pool)

def test_generate_monsxml():
    result = utils.generate_monsxml()
    print result

def test_collect_monaddrs():
    print utils.collect_monaddrs()

def test_assemble_volume_xml(pool, name):
    result = utils.assemble_volume_xml(pool, name)
    fd = open("/tmp/vdx", "a")
    fd.write(result)
    fd.close()

def test_domain_exists(domain):
    print utils.domain_exists(domain)

# test_check_pool("tinyiso2")
# test_collect_monaddrs()
# test_generate_monsxml()
# test_assemble_volume_xml("volumes", "test-CentOS-7.2-1")
# test_domain_exists("2nstance-0000009d")

def test_bridge_exists(bridge):
    return utils.bridge_exists(bridge)

# print "%s%s" % ("####", test_bridge_exists("br0-demo"))

def test_bridge_has_interface(bridge, vif):
    return utils.__bridge_has_interface(bridge, vif)
# print test_bridge_has_interface("br0-ea463ca94", "wan-ea463ca94")
# print test_bridge_has_interface("br0-ea463ca94", "wan")

def test_device_exists(dev):
    return utils.device_exists(dev)
# print test_device_exists("brx-demo")
# print test_device_exists("br0-demo")

def test_device_up(dev):
    return utils.device_up(dev)
# print test_device_up("br0-demo")

def test_command_supported(cmd):
    return utils.command_supported(cmd)
# print test_command_supported("virsh")
# print test_command_supported("qt")
print test_command_supported("mkisofs")

def test_ovscmd_supported():
    return utils.ovscmd_supported()
# print test_ovscmd_supported()

def test_brcmd_supported():
    return utils.brcmd_supported()
# print test_brcmd_supported()

def test_bridge_exists(bridge):
    return utils.bridge_exists(bridge)
# print test_bridge_exists("brx-demo")
# print test_bridge_exists("br0-demo")

def test_add_bridge(bridge):
    return utils.add_bridge(bridge)
# print test_add_bridge("br0xyz")

def test_ovswitch_exists(ovswitch):
    return utils.ovswitch_exists(ovswitch)
# print test_ovswitch_exists("br-io")
# print test_ovswitch_exists("br-wan")

def test_connect_ovs_to_bridge(ovs, device, bridge):
    return utils.connect_ovs_to_bridge(ovs, device, bridge)
# print test_connect_ovs_to_bridge("br-wan", "wanxyz", "br0xyz")

def test_get_available_blk_target(domain):
    return utils.get_available_blk_target(domain)

# print test_get_available_blk_target("instance-000000b3")
# print test_get_available_blk_target("demo")

def test_persist(content, target):
    utils.persist(content, target)
# test_persist("<xml>Hello world!</xml>", "/root/1.xml")

def test_domain_stat(domain):
    print utils.domain_stat(domain)
# test_domain_stat("test")

def test_assemble_cdrom_xml(pool, cdrom_file):
    print utils.assemble_cdrom_xml(pool, cdrom_file)
# test_assemble_cdrom_xml("tinyiso", "systemrescuecd-x86")
# test_assemble_cdrom_xml(None, None)

def test_cdrom_in_first_order(domain):
    print utils.cdrom_in_first_order(domain)

# test_cdrom_in_first_order("test")

def test_reset_cdrom_index(domain, cdrom_order):
    print utils.reset_cdrom_index(domain, cdrom_order)

# test_reset_cdrom_index("test", 0)
#test_reset_cdrom_index("test", 1)

def test_ceph_blk_exists(pool, volume, user):
    return utils.ceph_blk_exists(pool, volume, user)
# print test_ceph_blk_exists("tinyiso", "systemrescuecd-x86", "tinyiso")
# print test_ceph_blk_exists("tinyiso2", "systemrescuecd-x86", "tinyiso")



