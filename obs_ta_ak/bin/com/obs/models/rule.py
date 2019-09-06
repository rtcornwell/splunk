#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel, BASESTRING
from com.obs.models.expiration import Expiration, NoncurrentVersionExpiration
from com.obs.models.transition import Transition, NoncurrentVersionTransition

class Rule(BaseModel):

    allowedAttr = {'id': BASESTRING, 'prefix': BASESTRING, 'status': BASESTRING, 'expiration': Expiration, 'noncurrentVersionExpiration': NoncurrentVersionExpiration,
                   'transition': [Transition, list], 'noncurrentVersionTransition': [NoncurrentVersionTransition, list]}

    def __init__(self, id=None, prefix=None, status=None, expiration=None, noncurrentVersionExpiration=None, transition=None, noncurrentVersionTransition=None):
        self.id = id
        self.prefix = prefix
        self.status = status
        self.expiration = expiration
        self.noncurrentVersionExpiration = noncurrentVersionExpiration
        self.transition = transition
        self.noncurrentVersionTransition = noncurrentVersionTransition
