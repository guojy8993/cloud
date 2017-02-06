#! /usr/bin/python
# -*- coding: utf-8 -*-

from subprocess import Popen, PIPE
from cloud.common import utils
from cloud import config
from cloud import logger
import re
import os
import shutil
import uuid

log = logger.getLogger()

def sep_mac(mac):
    mac = mac.lower()
    if mac.count(":") == 5:
        return mac
    else:
        return "%s:%s:%s:%s:%s:%s" % (mac[0:2],mac[2:4],mac[4:6],mac[6:8],mac[8:10],mac[10:12])

class Network(object):
    def __init__(self):
        self.network_dir = config.network_scripts
        self.ext_gw_mac = "00:00:0c:07:ac:09"
        self.ext_dev_mac = "00:0d:bd:c2:e4:00"
        self.ext_uplink_port = 32 
        self.ext_vlan_id = 80

        self.int_dev_mac = "00:08:e2:86:39:ca"
        self.int_gw_mac = "00:00:0c:07:ac:14"
        self.int_uplink_port = 34


    def __build_link(self, domain, lan_or_wan):
        bridge = config.bridge_name_format % {
            "bridge_prefix": config.int_bridge_prefix if "lan" in lan_or_wan else config.ext_bridge_prefix,
            "domain": domain
        }
        addbrg_result = utils.add_bridge(bridge)
        if addbrg_result:
            ovswitch = "br-%s" % lan_or_wan
            ovs_device = config.ovs_port_format % {
                "ovs_port_prefix": config.ovs_lan_port_prefix if "lan" in lan_or_wan else config.ovs_wan_port_prefix,
                "domain": domain
            }
            conn_result = utils.connect_ovs_to_bridge(ovswitch, ovs_device, bridge)
            log.debug("Connect Result: %s" % conn_result)
            return conn_result
        return False
            

    def build_network_links(self, domain):
        build_wan = self.__build_link(domain, "wan")
        log.debug("Build_WAN: %s" % build_wan)
        if build_wan:
            build_lan = self.__build_link(domain, "lan")
            return build_lan
        return False

    def teardown_network_links(self, domain):
        pass

    def read_flows(self,**args):
        if "bridge" not in args or not args["bridge"]:
            return {"code":0,"message":"OVS bridge not specified !"}
        bridge = args["bridge"]

        check_bridge = "ovs-vsctl br-exists %s" % bridge
        code = os.system(check_bridge)
        if code > 0:
            return {"code":0,"message":"OVS bridge does not exist !"}

        dump_flows = "ovs-ofctl dump-flows %s" % bridge
        result = Popen(dump_flows, stdout=PIPE, shell=True).stdout.read()
        retv = ""
        for line in result.splitlines():
            if "NXST_FLOW" not in line and len(line.strip()) > 0:
                tmp = ",".join([ seg for seg in line.split(", ")
                                 if "cookie" not in seg \
                                     and "duration" not in seg \
                                     and "n_packets" not in seg  \
                                     and "n_bytes" not in seg \
                                     and "idle_age" not in seg  \
                                     and "hard_age" not in seg ])
                retv = "%s%s\n" % (retv, tmp)
        return {"code":0,"message":"OK","result":"%s" % retv}
    
    def ensure_access_for_clouddb(self, **args):
        if "ip_list" not in args or not args["ip_list"]:
            return {"code":0,"message":"black-list ip(s) needed specified !"}
        ips = args["ip_list"]
        try:
            ips = ips.split(",")
        except Exception:
            return {"code":0,"message":"black-list string malformed. !"}
        tmp_flows = "/tmp/clouddb_access"
        if os.path.exists(tmp_flows):
            os.remove(tmp_flows)
        template = "table=0,priority=100,ip,nw_dst=%s,dl_dst=%s actions=output:%d"
        with open(tmp_flows, "a") as fd:
            for ip in ips:
                if len(ip.strip()) == 0:
                    continue
                flow = template % (ip, self.int_gw_mac, self.int_uplink_port)
                fd.write("%s\n" % flow)
            fd.close()
        apply_flows = "ovs-ofctl add-flows br-lan %s" % tmp_flows
        errinfo = Popen(apply_flows, shell=True, stderr=PIPE).stderr.read()
        if errinfo is not None and len(errinfo.strip()) > 0:
            return {"code":0,"message":"Fail to add flows with command '%s' : %s"%(apply_flows, errinfo)}
        else:
            return {"code":1,"message":"success"}

    def add_flows_for_net_node(self, **args):
        if "bridge" not in args or not args["bridge"]:
            return {"code":0,"message":"OVS bridge not specified !"}
        bridge = args["bridge"]
        if "br-lan" != args["bridge"] and "br-wan" != args["bridge"]:
            return {"code":0,"message":"only br-wan or br-lan allowed !"}
        script_path = "%s%s" % (self.network_dir, "net_refresh_ovs_flows")
        apply_net_flows = "/bin/sh %s %s" % (script_path, bridge)
        errinfo = Popen(apply_net_flows, shell=True, stderr=PIPE).stderr.read()
        
        if errinfo is not None and len(errinfo.strip()) > 0:
            return {"code":0,"message":"Fail to add flows with command '%s' : %s"%(apply_net_flows, errinfo)}
        else:
            return {"code":1,"message":"success"}

    def add_flows_for_comp_node(self, **args):
        if "bridge" not in args or not args["bridge"]:
            return {"code":0,"message":"OVS bridge not specified !"}
        bridge = args["bridge"]
        if "br-lan" != args["bridge"] and "br-wan" != args["bridge"]:
            return {"code":0,"message":"only br-wan or br-lan allowed !"}
        script_path = "%s%s" % (self.network_dir, "com_refresh_ovs_flows")
        apply_comp_flows = "/bin/sh %s %s" % (script_path, bridge)
        errinfo = Popen(apply_comp_flows, shell=True, stderr=PIPE).stderr.read()
        if errinfo is not None and len(errinfo.strip()) > 0:
            return {"code":0,"message":"Fail to add flows with command '%s' : %s"%(apply_comp_flows, errinfo)}
        else:
            return {"code":1,"message":"success"}        
        
    def remove_flows(self,**args):
        """
        Network node only
        """
        if "bridge" not in args or not args["bridge"]:
            return {"code":0,"message":"OVS bridge not specified !"}

        if "domain_ip" not in args or not args["domain_ip"]:
            return {"code":0,"message":"Domain IP need to be specified !"}

        if "br-lan" in args["bridge"] and "vni" not in args:
            return {"code":0,"message":"Domain network vni not specified !"}

        if "br-wan" in args["bridge"] and "vm_mac" not in args:
            return {"code":0,"message":"MAC of Domain need to be specified !"}

        tmp_flows = "/tmp/remove_net_%s_flows.txt" % (args["domain_ip"])
        if os.path.exists(tmp_flows):
            os.remove(tmp_flows)
    
        remove_flow_template = "%s%s"%(self.network_dir, "remove_net_%s_template"%("wan" if "br-wan" in args["bridge"] else "lan"))
        with open(remove_flow_template, "r") as fd:
            flows = fd.read()
            fd.close()

        with open(tmp_flows,"a") as fd:
            flows = flows.replace('SRC_IP','%s'%args["domain_ip"])\
                         .replace('BRIDGE', '%s'%args["bridge"])
            if "br-wan" in args["bridge"]:
                flows = flows.replace('QMAC', '%s'%args["vm_mac"])
            if "br-lan" in args["bridge"]:
                flows = flows.replace('VM_VNI', '%s'%args["vni"])
            fd.write(flows)
            fd.close()

        apply_flows = "/bin/bash %s" % tmp_flows
        errinfo = Popen(apply_flows,shell=True,stderr=PIPE).stderr.read()
        if errinfo is not None and len(errinfo.strip()) > 0:
            return {"code":0,"message":"Fail to add flows with file '%s' : %s"%(tmp_flows,errinfo)}
        else:
            return {"code":1,"message":"success"}
    
    def add_flows(self,**args):
        """
        Network node only
        """
        if "bridge" not in args or not args["bridge"]:
            return {"code":0,"message":"OVS bridge not specified !"}
        if "domain_ip" not in args or not args["domain_ip"]:
            return {"code":0,"message":"Domain IP need to be specified !"}
        if "host_ip" not in args or not args["host_ip"]:
            return {"code":0,"message":"Host IP need to be specified !"}
        if "gateway_ip" not in args or not args["gateway_ip"]:
            return {"code":0,"message":"Gateway of Domain IP need to be specified !"}
        if "vm_mac" not in args or not args["vm_mac"]:
            return {"code":0,"message":"MAC of Domain need to be specified !"}
        if "br-lan" in args["bridge"] and "vni" not in args:
            return {"code":0,"message":"VNI need to be specified !"}
 
        if "br-lan" in args["bridge"]:
            self.int_gw_mac = args["sw_gw_mac"]
            self.int_dev_mac = args["sw_dev_mac"]
            self.int_uplink_port = args["uplink_port"]
        elif "br-wan" in args["bridge"]:
            self.ext_gw_mac = args["sw_gw_mac"]
            self.ext_dev_mac = args["sw_dev_mac"]
            self.ext_uplink_port = args["uplink_port"]

        def get_host_port(host):
            host_ofport_name = "vxlan%s"%host
            find_ofport = "ovs-vsctl get Interface %s ofport" % host_ofport_name
            find_ofport_result = Popen(find_ofport,shell=True,stdout=PIPE).stdout.read()
            if "no row" in find_ofport_result.strip():
                return None
            else:
                return find_ofport_result.strip()
        ofport = get_host_port(args["host_ip"])
        if not ofport:
            return {"code":0,"message":"Tunnel between Host %s and Network node broken !" % args["host_ip"]}
        tmp_flows = "/tmp/add_%s_%s_flows" % (args["host_ip"],args["domain_ip"])
        if os.path.exists(tmp_flows):
            os.remove(tmp_flows)
        flow_template = "%s%s" % (self.network_dir, "add_net_%s_template"%("wan" if args["bridge"] == "br-wan" else "lan"))

        with open(flow_template, "r") as fd:
            flows = fd.read()
            fd.close()
 
        with open(tmp_flows,"a") as fd:
            qflows = flows.replace('HOST_PORT','%s'%ofport.strip())\
                          .replace('SRC_IP','%s'%args["domain_ip"])\
                          .replace('GW_IP','%s'%args["gateway_ip"])\
                          .replace('QMAC', '%s'%(sep_mac(args["vm_mac"])))\
                          .replace('GW_MAC', '%s'%(self.ext_gw_mac if args["bridge"] == "br-wan" else self.int_gw_mac))\
                          .replace('LINK_PORT','%s'%(self.ext_uplink_port if args["bridge"] == "br-wan" else self.int_uplink_port))\
                          .replace('DEV_MAC','%s'%(self.ext_dev_mac if args["bridge"] == "br-wan" else self.int_dev_mac))
            if "br-lan" in args["bridge"]:
                qflows = qflows.replace('VM_VNI', '%s'%args["vni"])
            fd.write(qflows)
            fd.close()
        
        apply_flows = "ovs-ofctl add-flows %s %s" % (args["bridge"],tmp_flows)
        errinfo = Popen(apply_flows,shell=True,stderr=PIPE).stderr.read()
        if errinfo is not None and len(errinfo.strip()) > 0:
            return {"code":0,"message":"Fail to add flows with file '%s' : %s"%(tmp_flows,errinfo)}
        else:
            return {"code":1,"message":"success"}

    def add_vxlan_flows(self,**args):
        """
        Compute node only
        """
        if "bridge" not in args:
            return {"code":0,"message":"OVS bridge not specified !"}
        if "instance_name" not in args:
            return {"code":0,"message":"Domain name not specified !"}

        if "vlan_id" not in args:
            return {"code":0,"message":"Ip vlan id not specified !"}
        
        if "ip" not in args:
            return {"code":0,"message":"Domain Ip not specified !"}
        if "vxlan_port" not in args:
            return {"code":0,"message":"Domain vxlan_port not specified !"}
        vxlan_port = args["vxlan_port"]
        vlan_id = args["vlan_id"]
        domifinfo = "virsh domiflist %s" % args["instance_name"]
        devices = Popen(domifinfo,shell=True,stdout=PIPE).stdout.read()
        if "bridge" not in devices:
            return {"code":0,"message":"Domain or ovs bridge may not exist!"}
        keyword = "br0" if args["bridge"] == "br-wan" else "br1"
        line = [qline for qline in devices.split("\n") if keyword in qline ][0]
        mac = line.split()[4].strip()
        ovs_port_prefix = "wan" if args["bridge"] == "br-wan" else "lan"
        device = "%s%s" % (ovs_port_prefix,args["instance_name"])
        desc = "ovs-vsctl get Interface %s ofport"%device
        js = Popen(desc,shell=True,stdout=PIPE).stdout.read()
        ofport = js.strip()
        template_path = "%s%s" % (self.network_dir,"apply_%s_flows_template"%("wan" if args["bridge"] == "br-wan" else "lan"))
        tmpfile = "/tmp/%s_add_%s_vxlan_flows" % (args["instance_name"],"wan" if args["bridge"] == "br-wan" else "lan")

        fd = open(template_path, "r")
        flows = fd.read()
        fd.close()         
        
        if os.path.exists(tmpfile):
            os.remove(tmpfile)
        with open(tmpfile,"a") as fd:
            qflows = flows.replace('QPORT','%s'%ofport)\
                          .replace('QMAC','%s'%mac)\
                          .replace('SRC_IP','%s'%args["ip"])\
                          .replace('DEFAULT_VXLAN_PORT','%s'%vxlan_port)\
                          .replace('VLAN_ID', '%s'%vlan_id)
            if "br-lan" in args["bridge"]:
                qflows = qflows.replace('VNI','%s'%args["vni"])
            fd.write(qflows)
        apply_flows = "ovs-ofctl add-flows %s %s" % (args["bridge"],tmpfile)
        errinfo = Popen(apply_flows,shell=True,stderr=PIPE).stderr.read()
        if errinfo is not None and len(errinfo.strip()) > 0:
            return {"code":0,"message":"Fail to add flows with file '%s' : %s"%(tmpfile,errinfo)}
        else:
            return {"code":1,"message":"success"}       

        
    def remove_vxlan_flows(self,**args):
        """
        Compute node only
        """
        if "bridge" not in args:
            return {"code":0,"message":"OVS bridge not specified !"}
        if "instance_name" not in args:
            return {"code":0,"message":"Domain name not specified !"}
        if "ip" not in args:
            return {"code":0,"message":"Domain Ip not specified !"}
        if "vlan_id" not in args:
            return {"code":0,"message":"Ip vlan id not specified !"}
        if "br-lan" in args["bridge"] and "vni" not in args:
            return {"code":0,"message":"Domain network vni not specified !"}
        domifinfo = "virsh domiflist %s" % args["instance_name"]
        devices = Popen(domifinfo,shell=True,stdout=PIPE).stdout.read()
        if "bridge" not in devices:
            return {"code":0,"message":"Domain or ovs bridge may not exist!"}
        keyword = "br0" if args["bridge"] == "br-wan" else "br1"
        line = [line for line in devices.split("\n") if keyword in line ][0]
        mac = line.split()[4].strip()
        ovs_port_prefix = "wan" if args["bridge"] == "br-wan" else "lan"
        device = "%s%s" % (ovs_port_prefix,args["instance_name"])
        desc = "ovs-vsctl get Interface %s ofport"%device
        js = Popen(desc,shell=True,stdout=PIPE).stdout.read()
        ofport = js.strip()
        template_path = "%s%s" % (self.network_dir,"remove_%s_flows_template"%("wan" if args["bridge"] == "br-wan" else "lan"))
        tmpfile = "/tmp/%s_remove_%s_vxlan_flows" % (args["instance_name"],"wan" if args["bridge"] == "br-wan" else "lan")
        if os.path.exists(tmpfile):
            os.remove(tmpfile)

        with open(template_path, "r") as fd:
            flows = fd.read()
            fd.close()

        with open(tmpfile,"a") as fd:
            flows = flows.replace('QPORT','%s'%ofport)\
                         .replace('QMAC','%s'%mac)\
                         .replace('SRC_IP','%s'%args["ip"])\
                         .replace('BRIDGE','%s'%args["bridge"])\
                         .replace('VLAN_ID', '%s'%args["vlan_id"])
            if "br-lan" in args["bridge"]:
                flows = flows.replace('VNI','%s'%args["vni"])
            fd.write(flows)
            fd.close()

        remove_flows = "/bin/bash  %s" % tmpfile
        errinfo = Popen(remove_flows,shell=True,stderr=PIPE).stderr.read()
        if errinfo is not None and len(errinfo.strip()) > 0:
            return {"code":0,"message":"Fail to remove flows with file '%s' : %s"%(tmpfile,errinfo)}
        else:
            return {"code":1,"message":"success"}
        



    def init_flows(self, **args):
        """
        Add by haoyapei
        2016/03/02 kvm
        initialize inner_network flows
        """
        action = args["action"]
        instance_name = args["instance_name"]
        #instance_uuid = args["instance_uuid"]
        vport = args["instance_port"]
        mac = args["instance_mac"]
        """
        query_sql = "SELECT vport, mac FROM private_lan WHERE instance_name = '%s'" % instance_name
        query_info = db.execCloudSQL(query_sql)
        if len(query_info) == 0:
            return {"code": 0, "msg": "Fail to get private_lan vport and label for instance: %s." % instance_name}
        vport = query_info[0][0]
        mac = query_info[0][1]
        """
        script_file = "%s%s" % (self.network_dir, action)
        result = Popen("/usr/bin/bash %s %s %s %s" % (script_file, instance_name, vport, mac), stdout=PIPE, shell=True).stdout.read()
        if "succeed" not in result:
            raise Exception("Failed to initialize inner_network flows.")
        return {"code": 1, "message": "SUCCESS"}

    def del_flows(self, **args):
        """
        Add by haoyapei
        2016/03/22 kvm
        delete inner_network flows
        """
        action = args["action"]
        instance_name = args["instance_name"]
        script_file = "%s%s" % (self.network_dir, action)
        result = Popen("/usr/bin/bash %s %s" % (script_file, instance_name), stdout=PIPE, shell=True).stdout.read()
        if "succeed" not in result:
            raise Exception("Failed to delete inner_network flows.")
        return {"code": 1, "message": "SUCCESS"}

    def remove_ipv6_flows(self,**args):
        """
        Work for network node and compute node.
        """
        # 从参数中读取要取消流表的 IPv6 地址
        if "domain_ip" not in args or not args["domain_ip"]:
            return {"code":0,"message":"Domain IP need to be specified !"}

        # 检测要执行的刷流表命令文件是否已存在
        tmp_flows = "/tmp/remove_all_ipv6_%s_flows.txt" % (args["domain_ip"])
        if os.path.exists(tmp_flows):
            os.remove(tmp_flows)

        # 读取刷流表命令文件的模板
        remove_flow_template = "%s%s"%(self.network_dir, "remove_all_ipv6_template")
        with open(remove_flow_template, "r") as fd:
            flows = fd.read()
            fd.close()

        # 根据实际参数替换模板中的占位符
        with open(tmp_flows,"a") as fd:
            flows = flows.replace('SRC_IP','%s'%args["domain_ip"])\
                         .replace('BRIDGE', 'br-wan') # IPv6 只适用于 br-wan
            fd.write(flows)
            fd.close()

        # 应用流表命令文件
        apply_flows = "/bin/bash %s" % tmp_flows
        errinfo = Popen(apply_flows,shell=True,stderr=PIPE).stderr.read()
        if errinfo is not None and len(errinfo.strip()) > 0:
            return {"code":0,"message":"Fail to add flows with file '%s' : %s"%(tmp_flows,errinfo)}
        else:
            return {"code":1,"message":"success"}

    def add_ipv6_flows(self,**args):
        """
        Network node only
        """
        # 参数提取：虚拟机的 IPv6 地址
        if "domain_ip" not in args or not args["domain_ip"]:
            return {"code":0,"message":"Domain IP need to be specified !"}
        # 参数提取：虚拟机所在宿主的通道地址
        if "host_ip" not in args or not args["host_ip"]:
            return {"code":0,"message":"Host IP need to be specified !"}
        # 参数提取：网络节点的上联端口
        if "uplink_port" not in args or not args["uplink_port"]:
            return {"code":0,"message":"Uplink port need to be specified !"}
        # 本地准备额外的参数：网络节点上宿主机的端口
        def get_host_port(host):
            host_ofport_name = "vxlan%s"%host
            find_ofport = "ovs-vsctl get Interface %s ofport" % host_ofport_name
            find_ofport_result = Popen(find_ofport,shell=True,stdout=PIPE).stdout.read()
            if "no row" in find_ofport_result.strip():
                return None
            else:
                return find_ofport_result.strip()
        ofport = get_host_port(args["host_ip"])
        if not ofport:
            return {"code":0,"message":"Tunnel between Host %s and Network node broken !" % args["host_ip"]}

        # 检查是否已经存在上次操作生成的流表文件
        tmp_flows = "/tmp/add_net_ipv6_%s_%s_flows" % (args["host_ip"],args["domain_ip"])
        if os.path.exists(tmp_flows):
            os.remove(tmp_flows)

        # 读取指定的流表模板
        flow_template = "%s%s" % (self.network_dir, "add_net_ipv6_wan_template")
        with open(flow_template, "r") as fd:
            flows = fd.read()
            fd.close()

        # 将信息带入模板，生成流表文件
        with open(tmp_flows,"a") as fd:
            qflows = flows.replace('HOST_PORT','%s'%ofport.strip())\
                          .replace('SRC_IP','%s'%args["domain_ip"])\
                          .replace('LINK_PORT','%s'%args["uplink_port"])
            fd.write(qflows)
            fd.close()
        
        # 通过执行命令的方式应用生成的流表文件
        apply_flows = "ovs-ofctl add-flows %s %s" % ("br-wan",tmp_flows) # IPv6 只适用于外网
        errinfo = Popen(apply_flows,shell=True,stderr=PIPE).stderr.read()

        # 结果返回
        if errinfo is not None and len(errinfo.strip()) > 0:
            return {"code":0,"message":"Fail to add flows with file '%s' : %s"%(tmp_flows,errinfo)}
        else:
            return {"code":1,"message":"success"}

    def add_ipv6_vxlan_flows(self,**args):
        """
        Compute node only
        """
        # 参数提取：虚拟机名称
        if "instance_name" not in args:
            return {"code":0,"message":"Domain name not specified !"}
        # 参数提取：虚拟机 IPv6 地址的 vlan 信息
        if "vlan_id" not in args:
            return {"code":0,"message":"Ip vlan id not specified !"}
        # 参数提取：虚拟机的 IPv6 地址
        if "ip" not in args:
            return {"code":0,"message":"Domain Ip not specified !"}
        # 参数提取：vxlan 端口号
        if "vxlan_port" not in args:
            return {"code":0,"message":"Domain vxlan_port not specified !"}
        # 参数提取：虚拟机的 mac 地址。这个暂时忽略上层传过来的值，直接从本地系统中去获取
        domifinfo = "virsh domiflist %s" % args["instance_name"]
        devices = Popen(domifinfo,shell=True,stdout=PIPE).stdout.read()
        if "bridge" not in devices:
            return {"code":0,"message":"Domain or ovs bridge may not exist!"}
        keyword = "br0" #if args["bridge"] == "br-wan" else "br1"
        line = [qline for qline in devices.split("\n") if keyword in qline ][0]
        mac = line.split()[4].strip()
        # 本地准备额外的参数：获取用于网络节点连接的端口号
        ovs_port_prefix = "wan" #if args["bridge"] == "br-wan" else "lan"
        device = "%s%s" % (ovs_port_prefix,args["instance_name"])
        desc = "ovs-vsctl get Interface %s ofport"%device
        js = Popen(desc,shell=True,stdout=PIPE).stdout.read()
        ofport = js.strip()

        # 检查是否存在上次生成的流表文件
        tmpfile = "/tmp/%s_add_ipv6_%s_vxlan_flows" % (args["instance_name"],"wan")
        if os.path.exists(tmpfile):
            os.remove(tmpfile)

        # 读取指定的流表模板
        template_path = "%s%s" % (self.network_dir,"apply_ipv6_wan_flows_template")
        fd = open(template_path, "r")
        flows = fd.read()
        fd.close()
        
        # 将信息带入流表模板，生成流表文件
        with open(tmpfile,"a") as fd:
            qflows = flows.replace('QPORT','%s'%ofport)\
                          .replace('QMAC','%s'%mac)\
                          .replace('SRC_IP','%s'%args["ip"])\
                          .replace('DEFAULT_VXLAN_PORT','%s'%args["vxlan_port"])\
                          .replace('VLAN_ID', '%s'%args["vlan_id"])
            fd.write(qflows)

        # 通过执行命令的方式应用生成的流表文件
        apply_flows = "ovs-ofctl add-flows %s %s" % ("br-wan",tmpfile) # IPv6 只适用于外网
        errinfo = Popen(apply_flows,shell=True,stderr=PIPE).stderr.read()

        # 结果返回
        if errinfo is not None and len(errinfo.strip()) > 0:
            return {"code":0,"message":"Fail to add flows with file '%s' : %s"%(tmpfile,errinfo)}
        else:
            return {"code":1,"message":"success"}
