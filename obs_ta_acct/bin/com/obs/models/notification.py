#!/usr/bin/python
# -*- coding:utf-8 -*-

from com.obs.models.base_model import BaseModel, BASESTRING

class Notification(BaseModel):
    allowedAttr = {'topicConfigurations': list}

    def __init__(self, topicConfigurations=None):
        self.topicConfigurations = topicConfigurations

class TopicConfiguration(BaseModel):
    allowedAttr = {'id': BASESTRING, 'topic': BASESTRING, 'events': list, 'filterRules': list}

    def __init__(self, id=None, topic=None, events=None, filterRules=None):
        self.id = id
        self.topic = topic
        self.events = events
        self.filterRules = filterRules

class FilterRule(BaseModel):
    allowedAttr = {'name': BASESTRING, 'value': BASESTRING}
