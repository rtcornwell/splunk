#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel, BASESTRING

class Policy(BaseModel):

    allowedAttr = {'policyJSON': BASESTRING}
