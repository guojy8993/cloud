#! /usr/bin/python
# -*- coding: utf-8 -*-

from subprocess import Popen, PIPE
from cloud.service.image import Image as image_service
from cloud.service.disk import Disk as volume_service
from cloud.service.network import Network as network_service
from cloud.common import utils
from cloud import config
from cloud import logger
import copy
import os
import shutil
import re
import threading
import urllib
import uuid
import json

log = logger.getLogger()

def get_host():
    """Read hostname file to get machine name. """
    fd = open("/etc/hostname", "r")
    hostname = fd.read()
    fd.close()
    return hostname.strip()

def getLocalIP():
    return config.local_ip

class Instance(object):
    def __init__(self):
        self.instance_dir  = config.instance_scripts
        self.instance_data = config.instance_data
    
    def __image_exists(self, image):
        self.image = image_service()
        return self.image.image_exists(image)

    def __prepare_volume(self, name, image):
        self.volume = volume_service()
        return self.volume.prepare_volume(name=name, image=image)

    def __read_instance_template(self):
        source = "%s%s%s" % (self.instance_dir, os.sep, config.instance_template_name)
        if not os.path.exists(source):
            log.warn("instance template %s not found !" % source)
            return ""
        reader = open(source)
        return reader.read()
        
    def __init_domain_params(self, template, name, vcpu, memory, clock_offset, bootable_volume):
        console_path = "%s%s" %(self.instance_base_dir, "console.log")
        domain_uuid = uuid.uuid4()
        log.info("Prepare virshxml for %s(%s) with C%dM%d & %s" % (name, domain_uuid, vcpu, memory, bootable_volume))
        instance_template = template.format(name,
                                            domain_uuid,
                                            memory,
                                            memory,
                                            vcpu,
                                            clock_offset,
                                            bootable_volume,
                                            config.bridge_name_format % {"bridge_prefix": config.ext_bridge_prefix, "domain": name},
                                            config.bridge_name_format % {"bridge_prefix": config.int_bridge_prefix, "domain": name},
                                            console_path,
                                            console_path) 
        return instance_template

    def __persist_virshxml(self, xml, domain):
        target = "%s%s.xml" %(self.instance_base_dir, domain)
        utils.persist(xml, target)
        return target 

    def __ensure_instance_dir(self, instance_dir):
        if not os.path.exists(instance_dir):
            os.makedirs(instance_dir)

    def __build_network_links(self, domain):
        # build basic Layer2 for domain
        self.network = network_service()
        return self.network.build_network_links(domain)

    def create_instance(self, **args):
        if "name" not in args or not args["name"]:
            return {"code": 1, "message": "Domain name not specified !"}
        name = args["name"]
        domain_exists = utils.domain_exists(name)
        if domain_exists:
            return {"code": 1, "message": "Domain %s already exists!" % name}        
        self.instance_base_dir = "%s%s%s" % (self.instance_data, name, os.sep)
        self.__ensure_instance_dir(self.instance_base_dir)
        
        if "image" not in args or not args["image"]:
            return {"code": 1, "message": "Image name not specified !"}
        image_name = args["image"]
        if not self.__image_exists(image_name):
            return {"code": 1, "message": "Contact Administrator to upload image %s" % image_name}
        possible_os_type = image_name.lower().count("win")
        clock_offset = config.clock_offset_windows if possible_os_type else config.clock_offset_linux

        """ Prepare system volume """
        boot_volume = config.volume_name_format % {"domain": name, 
                                                   "type": config.volume_type_boot, 
                                                   "uuid":uuid.uuid4()
        }
        volumexml = self.__prepare_volume(name=boot_volume, image=image_name)
        """ As bootable volume, blk target should be set to 'vda' """
        volumexml = volumexml.replace("TARGET", "vda")
        persist_volume = "%s%s.xml" %(self.instance_base_dir, boot_volume)
        utils.persist(volumexml, persist_volume)

        build_link_result = self.__build_network_links(name)
        if not build_link_result:
            return {"code": 1, "message": "Fail to build links for domain %s" % name}
        instance_template = self.__read_instance_template()
        if len(instance_template) == 0:
            return {"code": 1, "message": "Tempalte file error"}
        
        if "vcpu" not in args or "memory" not in args:
            return {"code": 1, "message": "Domain flavor(vcpu,memory) not specified"}

        # MB -> KB
        memory = args["memory"] * 1024
        vcpu = args["vcpu"]
        instance_template = self.__init_domain_params(instance_template,
                                                      name,
                                                      vcpu,
                                                      memory,
                                                      clock_offset,
                                                      volumexml)
        virshxml = self.__persist_virshxml(instance_template, name)

        def define_domain_from_xml(xml):
            virshcmd = "virsh define %s" % xml
            output = Popen(virshcmd, shell=True, stdout=PIPE).stdout.read()
            log.info("Define domain %s with %s:%s" % (name, xml, output))
        define_domain_from_xml(virshxml)
        
        def start(name):
            virshcmd = "virsh start %s" % name
            output = Popen(virshcmd, shell=True, stdout=PIPE).stdout.read()
            log.info("Boot domain %s:%s" % (name, output))    
        start(name)
        return {"code": 0, "message": "Domain %s booting " % name} 

    def openVNC(self, **args):

        if "name" not in args or not args["name"]:
            return {"message": "Domain not specified", "code": 1} 
        name = args["name"]

        if not utils.domain_exists(name):
            return {"message": "Domain not found", "code": 1}

        if "running" not in utils.domain_stat(name):
            return {"message": "Domain not running", "code": 1}
        
        getDomainUUID = "virsh domuuid %s" % name
        result = Popen(getDomainUUID, shell=True, stdout=PIPE).stdout.read()
        guest_uuid = result.strip()
        vnc_port = self.__get_vncport(name)["vnc_port"]
        host = getLocalIP()
        request = {
              "action":"gen_token",
              "guest_uuid":guest_uuid,
              "host":host,
              "port":vnc_port
        }
        result = None
        try:
            fd = urllib.urlopen(config.vnc_gentoken_endpoint, json.dumps(request))
            result = fd.read()
            fd.close()
        except Exception:
            message = "Vnc token service not ready !"
            log.warn(message)
            return {"message": message, "code": 1}
        
        if "token" in result:
            result = json.loads(result)
            result.update({"code": 0, "message": "SUCCESS"})
            return result
        else:
            return {"code": 1, "message": "Fails for vnc token service: %s" % result}
        

    def describe_instance(self, **args):
        instance_name = args["instance_name"]
        cmdline = "virsh dominfo %s" % instance_name
        result = Popen(cmdline, stdout=PIPE, shell=True).stdout.read()
	log("describe_instance: %s" % result)
        if "Domain not found" in result:
            return "Domain of %s not found" % instance_name
        self.instance_info = result
        dominfo = {}
        dominfo.update(self.__get_host(instance_name))
	log("desc:get_host:%s"%dominfo)
        dominfo.update(self.__get_interfaces(instance_name))
	log("desc:get_interfaces:%s"%dominfo)
        dominfo.update(self.__get_blks(instance_name))
	log("desc:get_blks:%s"%dominfo)
        dominfo.update(self.__get_running_state(instance_name))
	log("desc:get_state:%s"%dominfo)
        dominfo.update(self.__get_uuid(instance_name))
	log("desc:get_uuid:%s"%dominfo)
        dominfo.update(self.__get_memory(instance_name))
	log("desc:get_memory:%s"%dominfo)
        dominfo.update(self.__get_cpus(instance_name))
	log("desc:get_cpus:%s"%dominfo)
        dominfo.update(self.__get_vncport(instance_name))
	log("desc:get_vnc:%s"%dominfo)
	log("describe_instance: end with result %s" % dominfo)
        return {"Status": "Success", "data": dominfo}

    def start_instance(self, **args):
        if "name" not in args or not args["name"]:
            return {"message": "Domain name not specified !", "code": 1}

        domain = args["name"]
        if not utils.domain_exists(domain):
            return {"message": "Domain %s not found !" % domain, "code": 1}
        
        stat = utils.domain_stat(domain)
        if "running" in stat:
            return {"message": "Domain %s already started !" % domain, "code": 0}

        virshcmd = "virsh start %s" % domain
        pipe = Popen(virshcmd,
                     shell=True,
                     stdout=PIPE,
                     stderr=PIPE)
        err = pipe.stderr.read()
        info = pipe.stdout.read()
        log.debug("Start domain %s: %s %s" % (domain, err, info))
        if info and "Domain %s started" % domain in info:
            return {"message": "Domain %s started !" % domain, "code": 0}
        else:
            return {"message": "Fail to start %s: %s" % (domain, err), "code": 1}
    
    def reboot_instance(self, **args):
        instance_name = args["instance_name"]
        action = args["action"]
        script_path = "%s%s" % (self.instance_dir, action)
        reboot = "/usr/bin/bash %s %s" % (script_path, instance_name)
        log(reboot)
        result = Popen(reboot, stdout=PIPE, shell=True).stdout.read()
        log(result)
        return {"message": "SUCCESS" if "OK" in result else "Error",
                "code": 1 if "OK" in result else 0}


    def resize_instance(self,**args):
	log(args)
        instance_name = args["instance_name"]
        action = args["action"]
        args["action"] = "describe_instance"
        old_config = self.describe_instance(**args)["data"]
	log(old_config)
        cpu_count = int(args["vcpu"]) if "vcpu" in args else old_config["cpu"]
        memory_KiB = int(args["memory"])*1000 if "memory" in args else int(old_config["memory"].split()[0].strip())
        script_path = "%s%s" % (self.instance_dir, action)
        resize = "/usr/bin/bash %s %s %s %s"%(script_path,instance_name,cpu_count,memory_KiB)
        log(resize)
        result = Popen(resize, stdout=PIPE, shell=True).stdout.read()
        log(result)
        return {"message": "SUCCESS" if "OK" in result else "Error",
                "code": 1 if "OK" in result else 0}
    
    def stop_instance(self, **args):
        if "name" not in args or not args["name"]:
            return {"message": "Domain name not specified !", "code": 1}

        domain = args["name"]
        if not utils.domain_exists(domain):
            return {"message": "Domain %s not found !" % domain, "code": 1}

        stat = utils.domain_stat(domain)
        if "shut off" in stat:
            return {"message": "Domain %s already stopped !" % domain, "code": 0}

        virshcmd = "virsh destroy %s" % domain
        pipe = Popen(virshcmd,
                     shell=True,
                     stdout=PIPE,
                     stderr=PIPE)

        err = pipe.stderr.read()
        info = pipe.stdout.read() 
        log.debug("Stop domain %s: %s %s" % (domain, err, info))
        if info and "Domain %s destroyed" % domain in info:
            return {"message": "Domain %s stopped !" % domain, "code": 0}
        else:
            return {"message": "Fail to stop Domain %s: %s" % (domain, err), "code": 1}

    def destroy_instance(self, **args):
        instance_name = args["instance_name"]
        action = args["action"]
        destroy_instance = "/usr/bin/bash %s %s" % ("%s%s" % (self.instance_dir, action), instance_name)
        log(destroy_instance)
        result = Popen(destroy_instance, stdout=PIPE, shell=True).stdout.read()
        return {"message": "SUCCESS", "code": 1}

    """attach iso to cdrom device"""
    def attach_iso(self,**args):
        instance_name = args["instance_name"]
        action = args["action"]
        iso_ftp = args["iso_ftp_url"]
        iso_name = iso_ftp.rsplit("/",1)[1]
        attachScript = "/usr/bin/bash %s %s %s %s" % ("%s%s"%(self.instance_dir,action),instance_name,iso_ftp,iso_name)
        log(attachScript)
        result_code = os.system(attachScript)/256
        message = "SUCCESS" if result_code == 0 else "Fail"
        return {"message":message,"code":1 if result_code == 0 else 0}   

    """detach iso from guest"""
    def detach_iso(self,**args):
        instance_name = args["instance_name"]
        action = args["action"]
        detachScript = "/usr/bin/bash %s %s" % ("%s%s"%(self.instance_dir,action),instance_name)
        log(detachScript)
        result_code = os.system(detachScript)/256
        message = "SUCCESS" if result_code == 0 else "Fail"
        return {"message":message,"code":result_code}


    """set interface mac"""
    def set_interface_mac(self,**args):
        log(args)
        instance_name = args["instance_name"]
        macAddress = args["macAddress"]
        newMacAddress = args["newMacAddress"]
        """reconfig guestXml with new mac address"""
        guestXmlPath = "/data/instance/%s/%s.xml"%(instance_name,instance_name)        
        backupXml = "virsh dumpxml %s"%instance_name
        """ensure guest running to generate complete guestXml"""
        tmp = copy.copy(args)
        tmp["action"] = "start_instance"
        self.start_instance(**tmp)      
        guestXml = Popen(backupXml,stdout=PIPE,shell=True).stdout.read()
        log(guestXml)
        log(guestXmlPath)
        writer = open(guestXmlPath,"w" if os.path.exists(guestXmlPath) else "a")
        validMac = False
        for line in guestXml.split("\n"):
            if macAddress in line:
                log(line)
                validMac = True
                line = newMacAddress.join(line.split(macAddress))
            writer.write("%s%s"%(line,"\n"))
        writer.close()
        if not validMac:
            return {
                    "code":0,
                    "message":"Specified mac address %s not found in guest %s"%(macAddress,instance_name)
                   }
        """redefine guest with fresh guestXml"""
        redefine_script = "%s%s"%(self.instance_dir,"redefine_instance")        
        redefine = "/usr/bin/bash %(redefine_script)s %(instance_name)s %(guestXmlPath)s"%{
                                                                        "redefine_script":redefine_script,
                                                                        "guestXmlPath":guestXmlPath,
                                                                        "instance_name":instance_name
                                                                      }
        log(redefine)
        result = Popen(redefine,stdout=PIPE,shell=True).stdout.read()
        return {"code":1 if "OK" in result else 0,"message":"SUCCESS" if "OK" in result else result}

    def get_instances(self, **args):
        get_instances = "virsh list --all"
        result = Popen(get_instances, stdout=PIPE, shell=True).stdout.read()
        lines = result.split("\n")[2:]
        log(lines)
        instances = []
        for line in lines:
            if len(line.strip()) > 0:
                instance_name = line.split()[1].strip()
                instances.append({"name": instance_name})
        return {"data": instances}

    """instance-ethernets"""
    def list_ethernets(self, **args):
        instance = args["instance_name"]
        ethernets = [eth for eth in self.__get_interfaces(instance)["nics"].values()]
        return {"data": ethernets}

    """instance-disk"""
    def list_disks(self, **args):
        instance_name = args["instance_name"]
        return {"data": [blk for blk in self.__check_out_blks(instance_name).values()]}

    def kvm_conn_mgmt(self, **args):
        instance_name = args["instance_name"]
        # nics = self.__get_interfaces(instance_name)
        macAddress = args["macAddress"]
        # wan_device = [desc["label"] for nic, desc in nics["nics"].iteritems() if macAddress in desc["macAddress"]][0].split(":")[-1]
        nic_status = args["connected"]
        wan_device = "br0%s" % instance_name
        kvm_conn_mgmt = "ip link set %s %s" % (wan_device, "up" if nic_status else "down")
        log(kvm_conn_mgmt)
        result = Popen(kvm_conn_mgmt, shell=True, stdout=PIPE).stdout.read()
        log("Set wan insterface(%s) of %s to %s ,and get result %s" % (wan_device, instance_name, nic_status, result))
        return {"code": 1, "message": "SUCCESS"}

    """bandwidth"""
    def set_bandwidth(self, **args):
        dominfo = self.describe_instance(**args)["data"]
        log(dominfo)
        enable_live_operation = "running" in dominfo["state"]
        bandwidth_Mb = int(str(args["bandwidth"]))
        nic_type = "wan"
        if "nic" in args:
            nic_type = args["nic"]
        instance_name = args["instance_name"]
        interface = self.__get_interfaces(instance_name)
        nics = interface["nics"]
        interface = nics[nic_type]
        set_bandwidth = "virsh domiftune --domain %(domain)s \
                                         --interface %(mac)s \
                                         --outbound %(outbound)d \
                                         --config %(live)s" % {
                                                                "domain": args["instance_name"],
                                                                "mac": interface["macAddress"],
                                                                "outbound": bandwidth_Mb * 125,
                                                                "live": "" if not enable_live_operation else "--live"
                                                             }
        log(set_bandwidth)
        result = Popen(set_bandwidth, stdout=PIPE, shell=True).stdout.read()
        log(result)
        return {"message": "Success", "code": 1}

    """inner method"""
    """host"""
    def __get_host(self, instance):
        vm_name = [line for line in self.instance_info.split("\n") if "Name" in line][0].split(":")[1].strip()
        return {"host": get_host(),"name":vm_name}

    """instance"""
    def __get_running_state(self, instance):
        running_state = [line for line in self.instance_info.split("\n") if "State" in line][0].split(":")[1].strip()
        return {"state": running_state}

    def __get_uuid(self, instance):
        uuid = [line for line in self.instance_info.split("\n") if "UUID" in line][0].split()[1]
        return {"uuid": uuid}

    def __get_memory(self, instance):
        memory = [line for line in self.instance_info.split("\n") if "Max memory" in line][0].split(":")[1]
        return {"memory": memory.strip()}

    def __get_cpus(self, instance):
        cpu = [line for line in self.instance_info.split("\n") if "CPU(s)" in line][0].split()[1]
        return {"cpu": int(cpu.strip())}

    """instance-disk"""
    def __get_blks(self, instance):
        return {"disks": self.__check_out_blks(instance)}

    def __check_out_blks(self, instance):
        check_out_klbs = "virsh domblklist %s" % instance
        result = Popen(check_out_klbs, stdout=PIPE, shell=True).stdout.read()
        disks_map = {}
        for line in result.split("\n"):
            if len(line.strip()) > 0 and line.startswith("vd"):
                mount_point = line.split()[0].strip()
                disk_file = line.split()[1].strip()
                disk = {
                         "capacityInGB":40 if "vda" in line else 0,
                         "isSystemPartition": "true" if "vda" in line else "false",
                         "UUID":disk_file.split("/")[-1],
                         "fileName":"%s:%s"%(get_host(),disk_file),
                         "label":mount_point
                       }
                disks_map.update({mount_point:disk})
        return disks_map
   
    """Set Iops"""
    def set_disk_iops(self,**args):
        instance_name = args["instance_name"]
        disk = args["disk_uuid"]
        iops = int(args["iops"])
        dominfo = "virsh dominfo %s" % instance_name
        domdetails = Popen(dominfo, stdout=PIPE, shell=True).stdout.read()
        live = "running" in domdetails
        if "system" in disk:
            device = "vda"
        else:
            get_blks = "virsh domblklist %s" % instance_name
            blks = Popen(get_blks, stdout=PIPE, shell=True).stdout.read()
            for line in blks.split("\n"):
                if disk in line:
                    device = line.split()[0].strip()
                    break
        if device is None:
            return {"message":"Device %s not found " % disk ,"code":0}
        setblktune = "virsh blkdeviotune     \
                    --domain %(domain)s   \
                    --device %(device)s     \
                    --read-iops-sec %(riops)d \
                    --write-iops-sec %(wiops)d   \
                    %(live)s --config" % {
                                "domain":instance_name,
                                "device":device,
                                "riops":iops,
                                "wiops":iops,
                                "live": "--live" if live else ""
                    }
        log(setblktune)
        retv = Popen(setblktune, stdout=PIPE, shell=True).stdout.read()
        log(retv)
        success = len(retv.strip()) == 0
        return {"message":"SUCCESS" if success else retv,"code":1 if success  else 0}

    """Vnc Port"""
    def __get_vncport(self,instance):
        get_vnc = "virsh vncdisplay %s" % instance
        result = Popen(get_vnc, stdout=PIPE, shell=True).stdout.read()
	if "error" in result:
		return {"vnc_port":-1}
        vnc_port = result.strip().split(":")[1]
        return {"vnc_port":int(vnc_port) + 5900}

    """interface"""
    def __get_interfaces(self, instance):
        get_interfaces = "virsh domiflist %s" % instance
        result = Popen(get_interfaces, stdout=PIPE, shell=True).stdout.read()
        nics = {}
        for line in result.split("\n"):
            if "br0" in line:
                device = line.split()[0]
                nics.update({"wan": {
                                      "macAddress": line.split()[4],
                                      "networkLabelName":"br-wan",
                                      "connected": "true" if "up" in self.__get_interface_status(device) else "false",
                                      "startConnected":"true",
                                      "label":"%s:%s:%s"%(get_host(),"br-wan",device),
                                      "isInternet":"true"}})
            if "br1" in line:
                device = line.split()[0]
                nics.update({"lan": {
                                      "macAddress": line.split()[4],
                                      "networkLabelName":"br-lan",
                                      "connected": "true" if "up" in self.__get_interface_status(device) else "false",
                                      "startConnected":"true",
                                      "label":"%s:%s:%s"%(get_host(),"br-lan",device),
                                      "isInternet":"false"}})
        log("===== IFs: %s" % nics)
        return {"nics": nics}

    def __get_interface_status(self, nic_device):
        if "-" in nic_device:
            return "down"
        get_interface_status = "ip -o link show %s" % nic_device
        log(get_interface_status)
        line = Popen(get_interface_status, shell=True, stdout=PIPE).stdout.read()
        log(line)
        if "UNKNOWN" in line:
            return "up"
        elif "DOWN" in line:
            return "down"
        else:
            pass

    def create_local_snapshot(self, **args):
        if "instance_name" not in args:
            return {"code": 0, "message": "domain not specified !"}
        instance_name = args["instance_name"]
        blks = self.__check_out_blks(instance_name)
        if (len(blks.keys())) > 1:
            return { "code": 0, 
                     "message": "please detach data disks before making snapshots !"
            }
        create_local_snapshot = "virsh snapshot-create \
                                    --domain %(domain)s" % {"domain":instance_name}
        result = Popen(create_local_snapshot,
                        stdout=PIPE,
                        shell=True).stdout.read()
        match = (re.compile("^Domain snapshot [0-9]{10} created$")).match(result.strip())
        if not match:
            return {"code": 0, "message": "%s" % result}
        else:
            snapshot_name = re.findall("[0-9]{10}",result)[0]
            disp_snapshots = "virsh snapshot-list \
                                    --domain %(domain)s" % {"domain":instance_name}
            result = Popen(disp_snapshots,
                            stdout=PIPE,
                            shell=True).stdout.read()
            latest_snapshot = [ line 
                                for line in result.split("\n") 
                                if snapshot_name in line ][0]
            date = re.findall("[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}",
                                latest_snapshot)[0]
            return { "code":1,
                     "message":"success",
                     "snapshot":{
                                  "name":"%s"%snapshot_name,
                                  "create_time":"%s"%date
                     }
            }

    def delete_local_snapshot(self, **args):
        if "instance_name" not in args or "snapshot" not in args:
            return { "code":0,
                     "message":"domain or snapshot not specified !"
            }
        domain = args["instance_name"]
        snapshot = args["snapshot"]
        disp_snapshots = "virsh snapshot-list \
                                    --domain %(domain)s" % {"domain":domain}
        result = Popen(disp_snapshots,
                            stdout=PIPE,
                            shell=True).stdout.read()
        if snapshot not in result:
            return { "code":1,
                     "message":"warn:snapshot %(snapshot)s was removed already !" % {"snapshot":snapshot}
            }
        remove_snapshot = "virsh snapshot-delete --domain %(domain)s \
                    --snapshotname %(snapshot)s" % {"domain":domain,"snapshot":snapshot}
        result = Popen(remove_snapshot,
                            stdout=PIPE,
                            shell=True).stdout.read()
        match = (re.compile("^Domain snapshot [0-9]{10} deleted$")).match(result.strip()) is not None
        if match:
            return {"code":1,"message":"%s"%(result.strip())}
        else:
            return {"code":0,"message":"fail with '%s'"%(result.strip())}

    def restore_from_local_snapshot(self, **args):
        if "instance_name" not in args or "snapshot" not in args:
            return { "code":0,
                     "message":"domain or snapshot not specified !"
            }
        domain = args["instance_name"]
        snapshot = args["snapshot"]
        disp_snapshots = "virsh snapshot-list \
                                    --domain %(domain)s" % {"domain":domain}
        result = Popen(disp_snapshots,
                            stdout=PIPE,
                            shell=True).stdout.read()
        if snapshot not in result:
            return { "code":0,
                     "message":"snapshot or domain not exist !"
            }
        restore_snapshot = "virsh snapshot-revert   \
                                --domain %(domain)s    \
                                --snapshotname %(snapshot)s \
                                --force    \
                                --running" % {"domain":domain,"snapshot":snapshot}
        result = Popen(restore_snapshot,
                            stdout=PIPE,
                            shell=True).stdout.read()
        if len(result.strip()) == 0:
            return {"code":1,"message":"success"}
        else:
            return {"code":0,"message":"fail with '%s'"%(result.strip())}
    
    def create_cloud_snapshot(self, **args):
        if "instance_name" not in args:
            return { "code":0,
                     "message":"domain not specified !"
            }
        domain = args["instance_name"]
        script_path = "%s%s" % (self.instance_dir,"create_snapshot")
        create_snapshot = "/bin/bash %s %s" % (script_path,domain)
        result = Popen(create_snapshot,shell=True,stdout=PIPE).stdout.read()
        if "OK" not in result:
            return { "code":0,
                     "message":"fail with %s" % (result.strip())
            }
        snapshot_uuid = result.strip().rsplit("_",1)[1]
        return { "code":1,
                 "message":"success",
                 "snapshot":"%s"%snapshot_uuid
        }
    
    def delete_cloud_snapshot(self, **args):
        if "instance_name" not in args or "snapshot" not in args:
            return { "code":0,
                     "message":"domain or snapshot not specified !"
            }
        domain = args["instance_name"]
        snapshot = args["snapshot"]
        script_path = "%s%s" % (self.instance_dir,"delete_snapshot")
        delete_snapshot = "/bin/bash %s %s %s" % (script_path,domain,snapshot)
        result = Popen(delete_snapshot,shell=True,stdout=PIPE).stdout.read()
        if "OK" not in result:
            return { "code":0,
                     "message":"fail with %s" % (result.strip())
            }
        return { "code":1,
                 "message":"success"
        }

    def restore_from_cloud_snapshot(self, **args):
        if "instance_name" not in args or "snapshot" not in args:
            return { "code":0,
                     "message":"domain or snapshot not specified !"
            }
        domain = args["instance_name"]
        snapshot = args["snapshot"]
        script_path = "%s%s" % (self.instance_dir,"restore_from_snapshot")
        restore_from_snapshot = "/bin/bash %s %s %s" % (script_path,domain,snapshot)
        result = Popen(restore_from_snapshot,shell=True,stdout=PIPE).stdout.read()
        if "OK" not in result:
            return { "code":0,
                     "message":"fail with %s" % (result.strip())
            }
        return { "code":1,
                 "message":"success"
        }

    def read_console(self,**args):
        if "instance_name" not in args or not args["instance_name"]:
            return {"code":0,"message":"Domain name not specified !"}
        domain = args["instance_name"]
        domain_folder = "%(instance_data)s%(domain)s%(sep)s" % {
                                        "instance_data":self.instance_data,
                                        "domain":domain,
                                        "sep":os.sep
        }
        domain_console_log = "%s%s"%(domain_folder,"console.log")
        console_last_read_pos = "%s%s"%(domain_folder,"last_read_pos")
       
        def read_pos(file):
            if not os.path.exists(file):
                fd = open(file,"a")
                pos = 0
                fd.write("%s"%pos)
            else:
                fd = open(file,"r")
                pos = int(fd.read().strip())
            fd.close()
            return pos

        def update_pos(file,pos):
            fd = open(file,"w")
            fd.write("%s"%pos)
            fd.close()
     
        if not os.path.exists(domain_console_log):
            return { "code":0,"message":"ensure that kvm starts with '--serial' option" }
        fd = open(domain_console_log,"r")
        pos = read_pos(console_last_read_pos)
        try:
            fd.seek(pos)
        except Exception:
            fd.seek(0)
        lines = fd.read()
        update_pos(console_last_read_pos,fd.tell())
        fd.close()
        return {"code":1,"message":lines}
   
    def __update_cdrom(self, domain, cdrom):

        domain_stat = utils.domain_stat(domain)
        live = "shut off" not in domain_stat

        virshcmd = "virsh update-device \
                          --domain %s \
                          --file %s --config %s" % (domain, cdrom, "--live" if live else "")
        
        pipe = Popen(virshcmd,
                     shell=True,
                     stdout=PIPE,
                     stderr=PIPE)
        info = pipe.stdout.read()
        erro = pipe.stderr.read()

        if info and "Device updated successfully" in info:
            return True
        else:
            log.warn("Fail to update %s with %s: %s" % (domain, cdrom, erro))
            return False
 
    def detach_cdrom(self, **args):

        if "name" not in args or not args["name"]:
            return {"message": 1, "code": "Domain name not specified !"}
        domain = args["name"]
        if not utils.domain_exists(domain):
            return {"message": 1, "code": "Domain %s not found !" % domain}

        empty_cdrom = utils.assemble_cdrom_xml(None, None)
        target = "/tmp/empty_cdrom.xml"
        utils.persist(empty_cdrom, target)

        if not self.__update_cdrom(domain, target):
            return {"message": "Fail to detach cdrom", "code": 1}

        cdrom_first = utils.cdrom_in_first_order(domain)
        if cdrom_first:
            result = utils.reset_cdrom_index(domain, 1)
            if not result:
                return {"message": "Fail to restore boot order", "code": 1}
        return {"message": "SUCCESS", "code": 0}

    def attach_cdrom(self, **args):

        if "name" not in args or not args["name"]:
            return {"message": 1, "code": "Domain name not specified !"}
        domain = args["name"]
        if not utils.domain_exists(domain):
            return {"message": 1, "code": "Domain %s not found !" % domain}
        
        if "iso_file" not in args or not args["iso_file"]:
            return {"message": "ISO file not specified !", "code": 1}
        iso_file = args["iso_file"]
        if not utils.ceph_blk_exists(config.ceph_iso_pool,
                                     iso_file,
                                     config.ceph_iso_pool_user):
            return {"message": "File %s not uploaded to pool %s" % (iso_file, config.ceph_iso_pool), "code": 1}
        
        if "iso_type" not in args:
            return {"message": "ISO file type not specified: 0 for PE,1 for Oracle/MSSQL,etc", "code": 1}
        iso_type = args["iso_type"]
 
        cdrom_xml = utils.assemble_cdrom_xml(config.ceph_iso_pool, iso_file)
        target = "%s%s%s%s.xml" % (config.instance_data, domain, os.sep, iso_file)
        utils.persist(cdrom_xml, target)
        
        if not self.__update_cdrom(domain, target):
            return {"message": "Cannot attach iso, read log for more details .", "code": 1}

        if iso_type > 0:
            return {"message": "SUCCESS", "code": 0}

        result = utils.reset_cdrom_index(domain, 0)
        if not result:
            return {"message": "Fail to reset boot order for CDROM, read log for details.", "code": 1}
        return {"message": "SUCCESS", "code": 0}
        
    def detach_tools(self, **args):
        if "instance_name" not in args or not args["instance_name"]:
            return {"code":0, "message":"Instance name required !"}
        instance = args["instance_name"]
        if "iso_type" not in args:
            return {"code":0, "message":"ISO type required ! 0 for PE and 1 for Oracle/MSSQL.."}
        iso_type = args["iso_type"]
        script_path = "%s%s" % (self.instance_dir,"detach_tools")
        command = "/bin/bash %s %s %d" % (script_path, instance, iso_type)
        log(command)
        result = Popen(command, shell=True, stdout=PIPE).stdout.read()
        log(result)
        if "OK" in result:
            return {"code":1, "message":"ISO Successfully detached !"}
        else:
            return {"code":0, "message":result}

    def execute(self, **args):

        if "script_name" not in args or not args["script_name"]:
            return {"code":0, "message":"Script name not specified !"}
        script = args["script_name"]
        
        if "interpreter" not in args or not args["interpreter"]:
            return {"code":0, "message":"Interpreter language not specified !"}
        interpreter = args["interpreter"].lower()

        script_path = "%s%s" % (self.instance_dir, script)
        if not os.path.exists(script_path):
            return {"code":0, "message":"Script file does not exist !"}

        def interpreter_supported(interpreter):
            test = "%s --help" % interpreter.lower()
            code = os.system(test)
            return code == 0

        if not interpreter_supported(interpreter):
            return {"code":0, "message":"Interpreter '%s' not ready !" % interpreter}

        param_list = "" if not "params" in args or not args["params"] else args["params"]
        command = "%s %s %s" % (interpreter, script_path, param_list)
        log(command)
        result = Popen(command, shell=True, stdout=PIPE).stdout.read()
        log(result)
        if "OK" in result:
            return {"code":1, "message":"%s" % result}
        else:
            return {"code":0, "message":"%s" % result}

    def __image_info(self,path):
        log("Image Info ....")
        if not os.path.exists(path):
            raise Exception("Instance disk file %s lost" % path)
        imageInfo = "qemu-img info %s" % path
        output = Popen(imageInfo,stdout=PIPE,shell=True).stdout.read()
        image_name = path if not "/" in path else path.rsplit("/",1)[1]
        info = {"path":path}
        for line in output.split("\n"):
            if "file format" in line:
                format = line.split(":")[1].strip()
                info.update({"format":format})
            elif "virtual size" in line:
                vsize = line.split()[2]
                info.update({"size":vsize})
        log("Image Info: %s" % info)
        return info

    def __domain_exists(self,domain):
        log("Domain %s Exists ? ..." % domain)
        doms = "virsh list --all"
        domall = Popen(doms,shell=True,stdout=PIPE).stdout.read()
        log("All Domains: \r\n%s" % domall)
        return (domain in domall)

    def __domain_running(self,domain):
        log("Domain %s running ? ..." % domain)
        dominfo = "virsh dominfo %s" % domain
        dominfo = Popen(dominfo,shell=True,stdout=PIPE).stdout.read()
        log("Domain state: \r\n%s" % domain)
        return "running" in dominfo

    def __pre_migration(self,**args):
        log("Start pre-migration with params: %s" % args)
        instance_name = args["instance_name"]
        if not self.__domain_exists(instance_name):
            raise Exception("Domain %s not found" % instance_name)
        if not self.__domain_running(instance_name):
            raise Exception("Live migration not allowed if domain not active")
       
        log("Instance %s exists and is running" % instance_name)
        blkinfo = "virsh domblklist %s" % instance_name
        blkinfo = Popen(blkinfo,shell=True,stdout=PIPE).stdout.read()
        blks = []
        for line in blkinfo.split("\n"):
            if line.strip().startswith("vd") or (line.strip().startswith("hda") and "iso" in line):
                path = line.split()[1].strip()
                blks.append(self.__image_info(path))

        # Notify remote peer host to create fake block devices and network
        notification = {
            "action":"pre_migration",
            "module":"instance",
            "instance_name":instance_name,
            "disks":blks
        }
        remoteCloudAPI = "http://%s:%d"%(args["destHost"],9999)
        log("Invoke %s do pre-migration job with params: %s" % (remoteCloudAPI, notification))
        df = urllib.urlopen(remoteCloudAPI,json.dumps(notification))
        result = df.read()
        df.close()
        log("Pre-migration result :%s" % result)
        return json.loads(result)



    def __prepare_guest_dir(self,guest_dir):
        log("Prepare instance folder ...")
        if os.path.exists(guest_dir):
            shutil.rmtree(guest_dir)
        os.makedirs(guest_dir)
        log("Instance folder %s prepared !" % guest_dir)

    def __prepare_fake_disk(self,disk):
        log("Pre-migration:create fake disk %s ..." % disk)
        imageCreate = "qemu-img create -f %(format)s %(path)s %(size)s" % disk
        log("pre-migration:create fake disk with command: %s" % imageCreate)
        output = Popen(imageCreate,shell=True,stdout=PIPE).stdout.read()
        log("pre-migration:create fake disk ,and output %s" % output)
        if not output.strip().startswith("Formatting"):
            raise Exception("Fail to create %(size)s %(format)s disk to %(path)s while migrating !" % disk)

    def __prepare_network(self,domain):
        script = "%s%s" % (self.instance_dir,"prepare_network")
        prepare_network = "/bin/bash %s %s" % (script, domain)
        result = Popen(prepare_network, shell=True, stdout=PIPE).stdout.read()
        log("Prepare network and result : %s" % result)

    def pre_migration(self,**args):
        log("Pre-migration with params: %s" % args)
        instance_name = args["instance_name"]
        disks = args["disks"]
        if self.__domain_exists(instance_name):
            delDomain = { "action":"destroy_instance",
                          "instance_name":instance_name
            }
            self.destroy_instance(**delDomain)
        self.__prepare_network(instance_name)
        guest_dir = disks[0]["path"].rsplit("/",1)[0].strip()
        log("pre-migration:creating instance directory %s" % guest_dir)
        self.__prepare_guest_dir(guest_dir)
        log("pre-migration:creating fake disks.")
        for disk in disks:
            self.__prepare_fake_disk(disk)
        return {"code": 1, "message": "SUCCESS"}


    def __start_migration(self,migration,outlog):
        migration_task = Popen(migration,
                                shell=True,
                                stderr=open(outlog,"a"))
        while True:
            try:
                code = migration_task.poll()
                if code is not None:
                    break
            except Exception:
                break


    def __run_migration(self,taskid,**args):
        instance_name = args["instance_name"]
        instance_dir = "%s%s"%(config.instance_data,instance_name)
        destHost = args["destHost"]
        migration_outfile = "%s/migration-task-%s-out.log"%(instance_dir,taskid)
        migration = "virsh migrate --domain %(instance)s --live \
                            --persistent --timeout %(timeout)d \
                            --abort-on-error \
                            --verbose  --copy-storage-all \
                            --desturi qemu+tcp://%(dest)s/system tcp://%(dest)s" % { "instance":instance_name,
                                                                       "timeout":24*3600,
                                                                       "dest":destHost }
        log(migration)
        task = threading.Thread(target=self.__start_migration,args=(migration,migration_outfile,))
        task.start()


    def live_migration(self,**args):
        log("Start live migration with request: %s" % args)
        result = self.__pre_migration(**args)
        log("Pre-migration done")
        if result["code"] == 0:
            taskid = str(uuid.uuid4())
            self.__run_migration(taskid,**args)
            return { "code":1,
                     "message":"migration started",
                     "taskid":taskid }
        else:
            return { "code":0,
                     "message":"pre-migration fails for reason: %s" % (result["message"] if result["message"] else "") }
       
    def onMigrationError(self,**args):
        instance_name = args["instance_name"]
        if self.__domain_exists(instance_name):
            delDomain = { "action":"destroy_instance",
                          "instance_name":instance_name }
            self.destroy_instance(**delDomain)
        elif os.path.exists("%s/%s"%(config.instance_data,instance_name)):
            shutil.rmtree("%s/%s"%(config.instance_data,instance_name))
        return { "code":1,"message":"delete %s and its data files." % instance_name }

    def __remove_migration_log(self,path):
        if os.path.exists(path):
            os.remove(path)

    def __on_migration_error(self,remote,removeTarget):
        onMigrationError = { "action":"onMigrationError",
                             "module":"instance",
                             "instance_name":removeTarget
        }
        peerClouAPI = "http://%s:%d"%(remote,9999)
        def notify_remote(remoteAPI,request):
            conn = urllib.urlopen(remoteAPI,json.dumps(request))
            log("Migration fails,notify remote to do closure job: %s" % (conn.read()))
            conn.close()
        closure = threading.Thread(target=notify_remote,args=(peerClouAPI,onMigrationError,))
        closure.start()

    def display_migration_progress(self,**args):
        instance_name = args["instance_name"]
        taskid = args["taskid"]
        destHost = args["destHost"]
        instance_dir = "%s%s"%(config.instance_data,instance_name)
        migration_outfile = "%s/migration-task-%s-out.log"%(instance_dir,taskid)
        reader = open(migration_outfile,"r")
        txt = reader.read()
        reader.close()
        if len(txt.strip()) == 0:
            return { "code":1,
                     "message":"preparing migration",
                     "progress":"0%" }
        
        if "error" in txt:
            """ migration fails for some system problem """
            self.__remove_migration_log(migration_outfile)
            """ do closure jobs,including:
            notifying remote peer to remove fake instance or disks
            remove migration outlog in current host
            """
            self.__on_migration_error(remote=destHost,removeTarget=instance_name)
            return { "code":0,
                     "message":txt,
                     "progress":"-1" }

        elif "Migration" in txt.rsplit("\r",1)[-1] and "100" not in txt.rsplit("\r",1)[-1]:
            """ migarion is on the way """
            return { "code":1,
                     "message":"migrating ....",
                     "progress":"%s%s" % (txt.rsplit("\r",1)[-1].split()[2].strip(),"%") }
        else:
            """ migration succeed """
            delDomain = { "action":"destroy_instance",
                          "instance_name":instance_name
            }
            """ remove orignal domain from current host """
            self.destroy_instance(**delDomain)
            return { "code":1,
                     "message":"migration succeed",
                     "progress":"100%" }
