#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel, BASESTRING
from com.obs.models.initiator import Initiator
from com.obs.models.owner import Owner

class Upload(BaseModel):
    allowedAttr = {'key': BASESTRING, 'uploadId':BASESTRING, 'initiator': Initiator,
                   'owner': Owner, 'storageClass': BASESTRING, 'initiated': BASESTRING}
