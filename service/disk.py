#! /usr/bin/python
# -*- coding: utf-8 -*-

from subprocess import Popen, PIPE
from cloud import config
from cloud import logger
from cloud.common import utils
from cloud.service.image import Image as image_service
import os
import re

log = logger.getLogger()

class Disk(object):
    def __init__(self):
        self.volume_pool = config.ceph_volume_pool
        self.image_pool = config.ceph_image_pool
        self.image = image_service()

    def __create_data_volume(self, name, size):
        if not utils.ceph_pool_exists(self.volume_pool):
            log.warn("Contact administartor to Add volume pool: %s" % self.volume_pool)
            return ""
        volume_exists = False
        if self.__check_volume(name):
            log.warn("Volume %s exists. Ignore possible errors and continue !" % name)
            volume_exists = True
        cephcmd = "rbd create %s --size %d --pool %s" % (name, size*1024, self.volume_pool)
        pipe = Popen(cephcmd, shell=True, stdout=PIPE, stderr=PIPE)
        output = pipe.stdout.read()
        errinfo = pipe.stderr.read()
         
        if (not output and not volume_exists) or (volume_exists and errinfo and "File exists" in errinfo):
            log.info("Volume %s created " % name)

        volumexml = utils.assemble_volume_xml(self.volume_pool, name)
        return volumexml

    def __check_volume(self, name):
        cephcmd = "rbd info %s --pool %s" % (name, self.volume_pool)
        errinfo = Popen(cephcmd, shell=True, stderr=PIPE).stderr.read()
        log.debug("Pre-creating volume %s, check: \n%s" % (name, errinfo))
        return not errinfo

    def __create_volume_from_image(self, name, imageref):
        if not utils.ceph_pool_exists(self.volume_pool):
            log.warn("Volume pool %s not found !" % self.volume_pool)
            return ""

        if not self.image.image_exists(imageref):
            log.warn("Image or snapshot %s not found !" % imageref)
            return ""
 
        volume_exists = False
        if self.__check_volume(name):
            log.warn("Volume %s exists. Ignore possible errors and continue !" % name)
            volume_exists = True
        cephcmd = "rbd clone %s/%s %s/%s" % (self.image_pool, imageref, self.volume_pool, name)
        pipe = Popen(cephcmd, shell=True, stdout=PIPE, stderr=PIPE)
        output = pipe.stdout.read()
        errinfo = pipe.stderr.read()
   
        if (not output and not volume_exists) or (volume_exists and errinfo and "File exists" in errinfo):
            log.info("Volume %s created from image %s " % (name, imageref))

        volumexml = utils.assemble_volume_xml(self.volume_pool, name)
        return volumexml

    def prepare_volume(self, name, image=None, size=None):        
        if not image and not size:
            log.warn("Create volume error: size and image cannt be null at the same time !")
            return False
        if image:
            log.debug("Create volume %s from image %s" % (name, image))
            return self.__create_volume_from_image(name, image)
        elif size and not image:
            log.debug("Create volume %s with size %d GB" % (name, size))
            return self.__create_data_volume(name, size)


    def create_volume(self, **args):

        if "name" not in args or not args["name"]:
            return {"message": "Volume name not specified", "code": 1}
        name = args["name"]

        if "instance_name" not in args or not args["instance_name"]:
            return {"message": "Domain name not specified", "code": 1}
        instance_name = args["instance_name"]
        
        if "volume_size" not in args \
                      or not args["volume_size"] \
                      or not isinstance(args["volume_size"], int):
            return {"message": "Volume size(GB) not specified", "code": 1}
        volume_size = args["volume_size"]
        
        image = args.get("image", None)
        volume_config = self.prepare_volume(name, image, volume_size)       
        if not len(volume_config):
            return {"message": "Fail to craete volume %s, read log file for details" % name, "code": 1}
        
        target = "%s%s%s%s.xml" % (config.instance_data, instance_name, os.sep, name)
        utils.persist(volume_config, target)
        return {"message": "Volume %s created" % name, "code": 0}        

    def attach_volume(self, **args):

        if "instance_name" not in args or not args["instance_name"]:
            return {"message": "Domain name not specified", "code": 1}
        instance_name = args["instance_name"]

        domain_exists = utils.domain_exists(instance_name)
        if not domain_exists:
            return {"message": "Domain %s not found" % instance_name, "code": 1}
        stat = utils.domain_stat(instance_name)
        live = "shut off" not in stat
        
        if "name" not in args or not args["name"]:
            return {"message": "Volume name not specified", "code": 1}
        name = args["name"]
       
        target = "%s%s%s%s.xml" % (config.instance_data, instance_name, os.sep, name)
        if not os.path.exists(target):
            return {"message": "Volume %s xml not found" % name, "code": 1}
        volume_config = open(target).read()
        log.debug("Volume: %s" % volume_config)

        if "TARGET" in volume_config:
            device = utils.get_available_blk_target(instance_name)
            volume_config, count = re.subn("'vd[a-z]'|'TARGET'", "'%s'" % device, volume_config)
            log.debug(volume_config)
            utils.persist(volume_config, target)
        
        virshcmd = "virsh attach-device \
                       --domain %s --file %s \
                       --config %s" % (instance_name, target, "--live" if live else "")
        
        pipe = Popen(virshcmd, shell=True, stdout=PIPE, stderr=PIPE)
        err = pipe.stderr.read()
        info = pipe.stdout.read()
        log.debug("Attach Disk with command '%s', and system output:'%s %s'" % (virshcmd, err, info))

        if info and "Device attached successfully" in info:
            return {"message": "Volume %s attached to domain %s" % (name, instance_name), "code": 0}
        else:
            return {"message": "Fail to attach %s to domain %s" % (name, instance_name), "code": 1}
        
    def __volume_attached(self, domain, volume):
        device = "%s/%s" % (self.volume_pool, volume)
        blks = "virsh domblklist %s" % domain
        blks = Popen(blks, shell=True, stdout=PIPE).stdout.readlines()
        blks = [ blk.split()[0] for blk in blks if device in blk ]
        return len(blks) > 0

    def detach_volume(self, **args):

        if "instance_name" not in args or not args["instance_name"]:
            return {"message": "Domain name not specified", "code": 1}
        instance_name = args["instance_name"]

        domain_exists = utils.domain_exists(instance_name)
        if not domain_exists:
            return {"message": "Domain %s not found" % instance_name, "code": 1}
        stat = utils.domain_stat(instance_name)
        live = "shut off" not in stat

        if "name" not in args or not args["name"]:
            return {"message": "Volume name not specified", "code": 1}
        name = args["name"]

        target = "%s%s%s%s.xml" % (config.instance_data, instance_name, os.sep, name)
        if not os.path.exists(target):
            return {"message": "Volume %s xml not found" % name, "code": 1}

        if not self.__volume_attached(instance_name, name):
            return {"message": "Volume %s already detached" % name, "code": 0}
        
        virshcmd = "virsh detach-device \
                                 --domain %s --file %s \
                                 --config %s" % (instance_name, target, "--live" if live else "")       
        pipe = Popen(virshcmd, shell=True, stdout=PIPE, stderr=PIPE)
        err = pipe.stderr.read()
        info = pipe.stdout.read()

        log.debug("Detach volume %s from domain %s: %s %s" % (name, instance_name, err, info))       
 
        if info and "Device detached successfully" in info:
            return {"message": "Volume %s detached from domain %s" % (name, instance_name), "code": 0}
        else:
            return {"message": "Fail to detach volume %s from domain %s" % (name, instance_name), "code": 1}


    def __remove_volume_from_backends(self, volume, pool=None):
        if not self.__check_volume(volume):
            return 0, "Volume %s already removed" % volume
        cephcmd = "rbd rm %s --pool %s" % (volume, pool)
        pipe = Popen(cephcmd, shell=True, stderr=PIPE)
        err = pipe.stderr.read()
        log.debug("Remove volume %s from pool %s: %s" % (volume, pool, err))
        if err and "Removing image: 100% complete" in err:
            return 0, "Volume %s removed" % volume
        else:
            return 1, "Fail to remove %s: %s" % (volume, err)
        

    def delete_volume(self, **args):

        if "instance_name" not in args or not args["instance_name"]:
            return {"message": "Domain name not specified", "code": 1}
        instance_name = args["instance_name"]        

        domain_exists = utils.domain_exists(instance_name)

        if "name" not in args or not args["name"]:
            return {"message": "Volume name not specified", "code": 1}
        name = args["name"]

        if domain_exists:
            if self.__volume_attached(instance_name, name):
                return {"message": "Volume %s still in use" % name, "code": 1}

        target = "%s%s%s%s.xml" % (config.instance_data, instance_name, os.sep, name)
        if os.path.exists(target):
            os.remove(target)

        code, message = self.__remove_volume_from_backends(name, self.volume_pool)
        return {"message": message, "code": code} 
