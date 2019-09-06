#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel, BASESTRING
from com.obs.models.date_time import DateTime

class Transition(BaseModel):

    allowedAttr = {'date': [BASESTRING, DateTime], 'days': int, 'storageClass': BASESTRING}

    def __init__(self, storageClass, date=None, days=None):
        self.storageClass = storageClass
        self.date = date
        self.days = days

class NoncurrentVersionTransition(BaseModel):

    allowedAttr = {'noncurrentDays': int, 'storageClass': BASESTRING}

    def __init__(self, storageClass, noncurrentDays):
        self.noncurrentDays = noncurrentDays
        self.storageClass = storageClass
