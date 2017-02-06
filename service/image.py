#! /usr/bin/python
# -*- coding: utf-8 -*-

from subprocess import Popen, PIPE
from cloud import config
from cloud import logger
from cloud.common import utils

log = logger.getLogger()


class Image(object):
    def __init__(self):
        self.pool = config.ceph_image_pool

    def __list_images(self, pool):
        if not utils.ceph_pool_exists(pool):
            log.warn("Ceph image pool %s not found" % pool)
            return ""
        else:
            cephcmd = "rbd ls --pool %s" % pool
            images = Popen(cephcmd,
                           shell=True,
                           stdout=PIPE).stdout.read()
            log.debug("Check images: \n%s" % images)
            return images

    def __snap_exists(self, pool, snap, image):
        cephcmd = "rbd snap ls %s --pool %s" % (image, pool)
        snaps = Popen(cephcmd, shell=True, stdout=PIPE).stdout.read()
        log.debug("Checkout snaps for image %s:\n %s" % (image, snaps))
        snaps = [ rec.split()[1]
            for rec in snaps.split("\n")[1:] if len(rec.strip()) > 0
        ]
        log.debug("Snaps for image %s: %s" % (image, snaps))
        for item in snaps:
            if snap == item:
                return True
        return False

    def image_exists(self, image):
        images = self.__list_images(self.pool)
        if "@" in image:
            base_image, snap_name = image.split("@")
            return self.__snap_exists(pool=self.pool, snap=snap_name, image=base_image)
        else:
            return image in images
