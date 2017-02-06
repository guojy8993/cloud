#! /usr/bin/python
# -*- coding: utf-8 -*-

from wsgiref.simple_server import make_server
from cloud.service.instance import Instance
from cloud.service.network import Network
from cloud.service.monitor import Monitor
from cloud.service.image import Image
from cloud.service.disk import Disk
from cloud.cloudinit.config_drive import CloudConfig
from cloud import logger
import json
import time

log = logger.getLogger()

def dispatch(**args):
    module = args["module"]
    func = args["action"]
    handler = None
    if module == "instance":
        handler = Instance()
    elif module == "disk":
        handler = Disk()
    elif module == "image":
        handler = Image()
    elif module == "network":
        handler = Network()
    elif module == "monitor":
        handler = Monitor()
    elif module == "cloudinit":
        handler = CloudConfig()
    
    retv = getattr(handler, func)(**args)
    return retv

def app(environ, start_response): 
    request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    request_body = environ['wsgi.input'].read(request_body_size)
    request_body = json.loads(request_body)
    headers = [('Content-type', 'application/json')]
    try:
        result = dispatch(**request_body)
        status = '200 OK'
        start_response(status, headers)
        return ['%s' % json.dumps(result)]
    except Exception as e:
        status = '500 Internal Server Error'
        start_response(status, headers)
        return ['%s' % str(e)]

httpd = make_server('', 8080, app)
httpd.serve_forever()
