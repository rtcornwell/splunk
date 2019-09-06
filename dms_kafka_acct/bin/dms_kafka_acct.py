# -*- coding:utf-8 -*-
################################################################################
# The program is designed to connect to the Open Telekom Cloud DMS queue which #
# has been setup to store Cloud Trace, Cloud Eye, or VPC Flow Logs (events)    #
# Its connects to Open Telekom Cloud (OTC) using a standard OTC account and    #
# and uses the resulting token to authenticate to DMS for pulling queued       #
# It is designed as a Splunk Modular Input Application to ingest and index     #
# events into Splunk.                                                          # 
# It can be run as Multiple Instances on Splunk to process seperate queues as  #                                                    #
# required.                                                                    #
# Author: Robert Cornwell                                                      #
# Company Huawei Technologies                                                  # 
# robert.cornwell@huawei.com                                                   #
# Python 2.7 Splunk 7.6                                                        # 
#                                                                              #
# API Documentation:                                                           #
# https://docs.otc.t-systems.com/en-us/api/dms/en-us_topic_0036182507.html     # 
# https://docs.otc.t-systems.com/en-us/cts/index.html                          #
# https://docs.splunk.com/Documentation/Splunk/7.2.5/AdvancedDev/ModInputsIntro#                                    
################################################################################
import sys
import time
from datetime import datetime
import urllib
import os
import urlparse
import xml.dom.minidom
import xml.sax.saxutils
import logging
import requests
import json
from __builtin__ import Exception
from requests.cookies import merge_cookies
from kafka import KafkaConsumer

# set up logging suitable for splunkd consumption
logging.root
logging.root.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.root.addHandler(handler)

# Setup the Scheme used for the Splunk Web Application Interface
SCHEME = """<scheme>
    <title>OTC Event Processing from DMS Queue</title>
    <description>Retrieve Open Telekom Cloud events from DMS</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>

    <endpoint>
        <args>
            <arg name="name">
                <title>Queue Name</title>
                <description>The Name of the DMS Queue to Proces. </description>
            </arg>
             <arg name="domain">
                <title>Domain</title>
                <description>OTC Domain Name</description>
            </arg>

            <arg name="projectid">
                <title>Project ID</title>
                <description>OTC Project ID</description>
            </arg>

            <arg name="queueid">
                <title>DMS Queue ID</title>
                <description>The ID of the DMS Queue</description>
            </arg>

            <arg name="consumergroupid">
                <title>DMS Consumer Group ID</title>
                <description>The ID of the DMS Queue Consumer Group ID</description>
            </arg>

            <arg name="username">
                <title>User Name</title>
                <description>OTC user account Name</description>
            </arg>

            <arg name="userpass">
                <title>User password</title>
                <description>OTC user accounts password</description>
            </arg>
      </args>
    </endpoint>
</scheme>
"""

def http_request(IAMurl, method, header, body=None, request_verify=False, request_cert=None, proxies=None, cookies=None):
    if body != None and type(body) != str:
        body = str(body)

    if header != None and type(header) != dict:
        try:
            header = json.loads(header)

        except Exception, e:
            print e
    if header == None:
        header = dict()

    # header.setdefault("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36")
    header.setdefault("User-Agent", "Splunk/dms_ta_acct")
    resp = requests.request(method, IAMurl, data=body, headers=header, verify=request_verify, cert=request_cert, proxies=proxies, cookies=cookies, allow_redirects=False, timeout=600)
    return resp

def http_post(IAMurl, headers, data, verify=False, cert=None, proxies=None, cookies=None):
     
    response = http_request(IAMurl, "post", headers, body=data, request_verify=verify, request_cert=cert, proxies=proxies, cookies=cookies)
    return response

def http_get(IAMurl, headers, verify=False, cert=None, proxies=None, cookies=None):

    response = http_request(IAMurl, "get", headers, request_verify=verify, request_cert=cert, proxies=proxies, cookies=cookies)
    return response

# Functiomn to authenticate with Azure SSO and return authentication Token
def get_ak(tokenStr):
    url = "https://iam.eu-de.otc.t-systems.com/v3.0/OS-CREDENTIAL/securitytokens"
    body = "{\"auth\":{\"identity\":{\"methods\":[\"token\"],\"token\":{\"id\":\"" + tokenStr + "\",\"duration-seconds\":\"900\"}}}}"
    Header = dict()
    Header.setdefault("X-Auth-Token", tokenStr)
    Header.setdefault("Content-type", "application/json;charset=utf8")
    resp = http_post(url, Header, body)
    data = json.loads(resp.text)
    ak = data["credential"]["access"]
    sk = data["credential"]["secret"]
    st = data["credential"]["securitytoken"]
    return (ak, sk, st)

# Function to authenticate and retrieve token
def get_token(UserName, UserPass, Domain):
    url = "https://iam.eu-de.otc.t-systems.com/v3/auth/tokens"
    token_body = "{\"auth\":{\"identity\":{\"methods\":[\"password\"],\"password\":{\"user\":{\"name\":\"" + UserName + \
           "\",\"password\":\"" + UserPass + "\",\"domain\": { \"name\":\"" + Domain + "\"}}}},\"scope\":{ \"domain\": {\
           \"name\":\"" + Domain + "\"}}}}"
    token_header = dict()
    token_header.setdefault("Content-type", "application/json")
    resp = http_post(url, token_header, token_body, verify=True, cert=None, proxies=None, cookies=None)
    tokenStr = resp.headers.get("X-Subject-Token")
    return (tokenStr)

def init_stream():
    sys.stdout.write("<stream>\n")

def fini_stream():
    sys.stdout.write("</stream>\n")

def send_event(data, edate):
    sys.stdout.write("<event>\n")
    sys.stdout.write("<time>"+ edate +"</time>\n")
    sys.stdout.write("<data>" + data + "</data>\n")
    sys.stdout.write("</event>\n")


def ackmessage(handlers, TokenID, ProjectID, QueueID, ConsumerGroupID):
    ackurl = "https://dms.eu-de.otc.t-systems.com/v1.0/" + ProjectID + "/queues/" + QueueID + \
             "/groups/"+ ConsumerGroupID +"/ack"
    i = 0
    # body = "{\"message\":[{\"handler\":\""+handler+"\",\"status\":\"success\"}]}"
    body_list = []
    body_list.append("{\"message\": [")
    for handler in handlers:
        body_list.append("{\"handler\": \"" + handler + "\",\"status\": \"success\"}")
        if ( len(handlers) > 1 and len(handlers) != (i+1) ) :
            body_list.append(",\n")
        i+=1
    body_list.append("]}")
    body = ''.join(body_list)
    body = json.loads(body)
    ack_body = json.dumps(body, indent= 4, encoding="ütf-8", sort_keys=True, separators=(',', ':'))
    ack_header = dict()
    ack_header.setdefault("Content-type", "application/json")
    ack_header.setdefault("X-Auth-Token", TokenID)
    resp = http_post(ackurl, ack_header, ack_body, verify=True, cert=None, proxies=None, cookies=None )
    return resp.status_code
    # return response.status_code
    # if resp.status_code == requests.codes.ok:
    #     return resp.status_code
    # else:
    #     logging.debug('errorCode:%s', resp.status_code)
    #     logging.debug('errorMessage:%s', resp.content)

    #     sys.exit(2)

# Connect to DMS and Query next messages in the queue to be processed. We also send accknowledgement on receipt.
def processqueue(TokenID, ProjectID, QueueID, ConsumerGroupID, max_msgs):

    DMSurl = "https://dms.eu-de.otc.t-systems.com/v1.0/" + ProjectID + "/queues/"+ QueueID + \
             "/groups/"+ ConsumerGroupID +"/messages?max_msgs="+ max_msgs +"&ack_wait=30"
    qheader = dict()
    qheader.setdefault("X-Auth-Token", TokenID)
    qheader.setdefault("Content-type", "application/json;charset=utf8")
    # Query DMS Queue and retrieve next 10 messages. If queue empty we return false. If an error occurs
    # we produce an exception and return false.
    time.sleep(5)
    resp = http_get(DMSurl, qheader, verify=True, cert=None, proxies=None, cookies=None)
    if resp.status_code == requests.codes.ok:
        if len(resp.content) > 2 : 
            Events = resp.json()
            MsgHandlers = []
            i = 0
            init_stream()
            for Event in Events:
                # Extract the SMN Message
                qmessages = json.loads(Event['message']['body'])
                # Extract the Trace Messages from SMN Message
                qmessage = json.loads(qmessages['message'])
                edate = qmessage['time']
                MsgHandler = Event['handler']
                MsgHandlers.append(MsgHandler)
                send_event(json.dumps(qmessage), edate)
                i += 1

            fini_stream()
            # Acknowledge the batch of messages just processed.
            time.sleep(5)
            if ackmessage(MsgHandlers, TokenID, ProjectID, QueueID, ConsumerGroupID) == 200:
               return True
            else:
               return False
        else:
            return False
    else:
        logging.debug('processqueue returned an error: errorCode:%s', resp.status_code)
        logging.debug('errorMessage:%s', resp.content)
        return False

# prints XML error data to be consumed by Splunk
def print_error(s):
    print "<error><message>%s</message></error>" % xml.sax.saxutils.escape(s)

def validate_conf(config, key):
    if key not in config:
        raise Exception, "Invalid configuration received from Splunk: key '%s' is missing." % key

# read XML configuration passed from splunkd
def get_config(): 
    config = {}

    try:
        # read everything from stdin passed by Splunk
        config_str = sys.stdin.read()

        # parse the config XML
        doc = xml.dom.minidom.parseString(config_str)
        root = doc.documentElement
        conf_node = root.getElementsByTagName("configuration")[0]
        if conf_node:
            logging.debug("XML: found configuration")
            stanza = conf_node.getElementsByTagName("stanza")[0]
            if stanza:
                stanza_name = stanza.getAttribute("name")
                if stanza_name:
                    logging.debug("XML: found stanza " + stanza_name)
                    config["name"] = stanza_name

                    params = stanza.getElementsByTagName("param")
                    for param in params:
                        param_name = param.getAttribute("name")
                        logging.debug("XML: found param '%s'" % param_name)
                        if param_name and param.firstChild and \
                           param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                            data = param.firstChild.data
                            config[param_name] = data
                            logging.debug("XML: '%s' -> '%s'" % (param_name, data))

        checkpnt_node = root.getElementsByTagName("checkpoint_dir")[0]
        if checkpnt_node and checkpnt_node.firstChild and \
           checkpnt_node.firstChild.nodeType == checkpnt_node.firstChild.TEXT_NODE:
            config["checkpoint_dir"] = checkpnt_node.firstChild.data

        if not config:
            raise Exception, "Invalid configuration received from Splunk."

        # just some validation: make sure these keys are present (required)
        validate_conf(config, "name")
        validate_conf(config, "domain")
        validate_conf(config, "projectid")
        validate_conf(config, "queueid")
        validate_conf(config, "consumergroupid")
        validate_conf(config, "username")
        validate_conf(config, "userpass")
        validate_conf(config, "checkpoint_dir")
    except Exception, e:
        raise Exception, "Error getting Splunk configuration via STDIN: %s" % str(e)

    return config

def do_scheme():
    print SCHEME

def get_validation_data(): # Read Sysargs passed by the splunk process.
    val_data = {}

    # read everything from stdin
    val_str = sys.stdin.read()

    # parse the validation XML
    doc = xml.dom.minidom.parseString(val_str)
    root = doc.documentElement

    logging.debug("XML: found items")
    item_node = root.getElementsByTagName("item")[0]
    if item_node:
        logging.debug("XML: found item")

        name = item_node.getAttribute("name")
        val_data["stanza"] = name

        params_node = item_node.getElementsByTagName("param")
        for param in params_node:
            name = param.getAttribute("name")
            logging.debug("Found param %s" % name)
            if name and param.firstChild and \
               param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                val_data[name] = param.firstChild.data

    return val_data

# Validation Routine called when user submits web data entry for the Applications.
def validate_arguments():
    pass

# Display Usage command format (For Debugging)
def usage():
    print "usage: %s [--scheme|--validate-arguments]"
    sys.exit(2)

# Test Splunk streaming
def test():
    sys.exit(0)

def run():
    #Read Parameters passed by Splunk Configuration
    # config          = get_config()
    # Instance        = config["name"]
    # Domain          = config["domain"]
    # ProjectID       = config["projectid"]
    # QueueID         = config["queueid"]
    # ConsumerGroupID = config["consumergroupid"]
    # UserName        = config["username"]
    # UserPass        = config["userpass"]

    Instance        = "dms_ta_acct//Cloudtrace"
    Domain          = "OTC00000000001000010501"
    ProjectID       = "bf74229f30c0421fae270386a43315ee"
    QueueID         = "06a20783-d0f7-4173-a85c-388c3547c143"
    ConsumerGroupID = "g-eea7c7cc-eae7-49b2-976d-b62471c62e35"
    UserName        = "robertcornwell"
    UserPass        = "Dallas@12651265"
    max_msgs        = "10"
    KafkaTopic      = "k-bf74229f30c0421fae270386a43315ee-0cee02b5-95ab-4776-8a88-f2c8adb2c865"
    msg = ""

    # Authenticate and return Token
    TokenID = get_token(UserName, UserPass, Domain)

    # Get Temporary AK/SK from IAM for User. Obs can only be access with AK/SK so we need a temporary key.
    ak, sk, TokenID = get_ak(TokenID)

    # sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required \
    #     access_key="your ak"
    # secret_key="your sk"
    # project_id="projectID";
    # To consume latest messages and auto-commit offsets
    consumer = KafkaConsumer(KafkaTopic, client_id='Splunk', group_id=ConsumerGroupID, bootstrap_servers=['dms-kafka.eu-de.otc.t-systems.com:37000'], 
                             sasl_mechanism="DMS", security_protocol="SASL_SSL", sasl_dms_ak=ak, sasl_dms_sk=sk, 
                             sasl_dms_projectid=ProjectID, ssl_check_hostname=False, 
                             ssl_certfile='client.truststore.jks')
                              

    for msg in consumer:
    # message value and key are raw bytes -- decode if necessary!
    # e.g., for unicode: `message.value.decode('utf-8')`
         print ("%s:%d:%d: key=%s value=%s" % (message.topic, message.partition,
                                               message.offset, message.key,
                                               message.value))

    # We will cycle throughthe DMS queue until no more messages are available.
    # while True:
    #     if processqueue(TokenID, ProjectID, QueueID, ConsumerGroupID, max_msgs) == False: 
    #         break
        
    #Flush the stdout to force splunk to process messages left over.
   

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            do_scheme()
        elif sys.argv[1] == "--validate-arguments":
            validate_arguments()
        elif sys.argv[1] == "--test":
            test()
        else:
            usage()
    else:
        run()

    sys.exit(0)
