#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author  guojy8993
# Date    2016/12/29

import logging
import config

logging.basicConfig(
    format="%(asctime)s %(module)s:%(funcName)s [%(levelname)s] %(message)s",
    filename=config.log_path,
    level=config.log_level)

logger = logging.getLogger(__name__)


def getLogger():
    return logger
