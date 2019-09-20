#!/usr/bin/python
# -*- coding:utf-8 -*-
# Splunk Application to import Object Storage CTS Logs.
# Written for EY using the EY Powershell Authentication script for Federated users.
 
import sys
import time
import urllib
import os
from com.obs.client.obs_client import ObsClient
import gzip
from cStringIO import StringIO
import urlparse
import xml.dom.minidom
import xml.sax.saxutils
import logging
import requests
import json
from __builtin__ import Exception
import subprocess

# set up logging suitable for splunkd consumption
logging.root
logging.root.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.root.addHandler(handler)

# Setup the Scheme used for the Splunk Web Application Interface
SCHEME = """<scheme>
    <title>OTC Log Processing with IdP SSO support</title>
    <description>Retrieve Open Telekom Cloud Logs from OBS</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>

    <endpoint>
        <args>
            <arg name="name">
                <title>Instance Name</title>
                <description>Provide a unique name for this Instance/Stanza. IE: Cloudtrace, VPCFlow</description>
            </arg>
            <arg name="idpname">
                <title>IDPNAme</title>
                <description>Enter the name of the IDP Definition used for authentication.</description>
            </arg>
             <arg name="obsendpoint">
                <title>Object Storage Endpoint</title>
                <description>Enter the name of the Endpoint for the OBS services.</description>
            </arg>
            <arg name="bucketname">
                <title>Bucketname</title>
                <description>Enter the name of the Bucket on OBS soring the log traces.</description>
            </arg>
            <arg name="prefix">
                <title>Log Prefix</title>
                <description>The The prefix defined in the trace log definition</description>
            </arg>
            <arg name="maxkeys">
                <title>Max Keys</title>
                <description>Enter the Max Keys parameter (100-1000). This is a tuning parameter for OBS Client</description>
            </arg>
            <arg name="username">
                <title>User Name</title>
                <description>Azure AD or Other user accounts</description>
            </arg>
            <arg name="userpass">
                <title>User password</title>
                <description>Azure AD or Other user accounts password</description>
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

    header.setdefault("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36")
    resp = requests.request(method, IAMurl, data=body, headers=header, verify=request_verify, cert=request_cert, proxies=proxies, cookies=cookies, allow_redirects=False, timeout=600)
    return resp

def http_post(IAMurl, headers, data, verify=False, cert=None, proxies=None, cookies=None):

    response = http_request(IAMurl, "post", headers, body=data, request_verify=verify, request_cert=cert, proxies=proxies, cookies=cookies)
    return response

def http_get(IAMurl, headers, verify=False, cert=None, proxies=None, cookies=None):
    
    response = http_request(IAMurl, "get", headers, request_verify=verify, request_cert=cert, proxies=proxies, cookies=cookies)
    return response

# Function to authenticate with Azure SSO and return authentication Token calling Powershell script
def get_token(UserName, UserPass):

    PowerShellPath = r'C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe'
    PowerShellCmd  = r'C:\\Program Files\\Splunk\\etc\\apps\\obs_ta_idp\\bin\\otc-get-token.ps1'
    
    p = subprocess.Popen([PowerShellPath,'-ExecutionPolicy','Bypass','-file',PowerShellCmd,UserName,UserPass]
        ,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    TokenID, err = p.communicate()
    rc = p.returncode
    if(err):
        raise Exception('Error: ' + str(err))

    return TokenID

# Function to request temporary AK/SK and security key https://docs.otc.t-systems.com/en-us/api/iam/en-us_topic_0097949518.html
def get_ak(TokenID):
    url = "https://iam.eu-de.otc.t-systems.com/v3.0/OS-CREDENTIAL/securitytokens"
    body = "{\"auth\":{\"identity\":{\"methods\":[\"token\"],\"token\":{\"id\":\"" + TokenID + "\",\"duration-seconds\":\"900\"}}}}"
    Header = dict()
    Header.setdefault("X-Auth-Token", TokenID)
    Header.setdefault("Content-type", "application/json;charset=utf8")
    resp = http_post(url, Header, body)
    data = json.loads(resp.text)
    ak = data["credential"]["access"]
    sk = data["credential"]["secret"]
    st = data["credential"]["securitytoken"]
    return (ak, sk, st)

def init_stream():
    sys.stdout.write("<stream>")

def fini_stream():
    sys.stdout.write("</stream>\n")

def send_event(buf, edate, source):
    sys.stdout.write("<event>\n")
    sys.stdout.write("<time>"+ str(edate) +"</time>\n")
    sys.stdout.write("<data>" + xml.sax.saxutils.escape(buf) + "</data>\n")
    sys.stdout.write("<source>" + source + "</source>\n")
    sys.stdout.write("</event>\n")

def send_done_key(source):
    sys.stdout.write("<event unbroken=\"1\"><source>")
    sys.stdout.write(xml.sax.saxutils.escape(source))
    sys.stdout.write("</source><done/></event>\n")

# get the data from the data flow
def read_gz_file(buffer):
    buf = StringIO(buffer)
    f = gzip.GzipFile(mode='rb', fileobj=buf)
    return f.read()

# Connect to OBS and Query all the objects in the Bucket to be processed. 
# Prefix and marker limit the search. Marker is a checkpoint of last run.
def processlogs(bucketClient, prefix=None, marker=None, max_keys=None, source=None):
    resp_list = bucketClient.listObjects(prefix=prefix, marker=marker, max_keys=max_keys, delimiter=None)
    if resp_list.status < 300:
        if resp_list.body:
            if resp_list.body.contents:
                i = 0
                for content in resp_list.body.contents:
                    resp_get = bucketClient.getObject(content.key, loadStreamInMemory=True)
                    if resp_get.status < 300:
                        init_stream()
                        StreamData = read_gz_file(resp_get.body.buffer)
                        # Parse individual events from json Data (trace events) and send event to splunk indexer.
                        # https://docs.otc.t-systems.com/en-us/usermanual/cts/en-us_topic_0030598500.html
                        # Each log may contain one or many events so we want to parse each event and process each individually.
                        Events = json.loads(StreamData)
                        for Event in Events:
                            # Convert timestamp in event from millisecond posix to seconds possix.
                            Event['time'] = int(round(Event['time'] / 1000))
                            Event['record_time'] = int(round(Event['record_time'] / 1000))
                            send_event(json.dumps(Event), Event['time'], source) 
                        fini_stream()
                    i += 1
                    sys.stdout.flush()
                return content.key, resp_list.body.next_marker
        return marker, None
    else:
        logging.debug('errorCode:%s', resp_list.errorCode)
        logging.debug('errorMessage:%s', resp_list.errorMessage)
        sys.exit(2)

# prints XML error data to be consumed by Splunk
def print_error(s):
    print "<error><message>%s</message></error>" % xml.sax.saxutils.escape(s)

def validate_conf(config, key):
    if key not in config:
        raise Exception, "Invalid configuration received from Splunk: key '%s' is missing." % key

def get_config(): # read XML configuration passed from splunkd
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
                            logging.debug("XML: '%s' -> '%s'" %
                                          (param_name, data))

        checkpnt_node = root.getElementsByTagName("checkpoint_dir")[0]
        if checkpnt_node and checkpnt_node.firstChild and \
           checkpnt_node.firstChild.nodeType == checkpnt_node.firstChild.TEXT_NODE:
            config["checkpoint_dir"] = checkpnt_node.firstChild.data

        if not config:
            raise Exception, "Invalid configuration received from Splunk."

        # just some validation: make sure these keys are present (required)
        validate_conf(config, "name")
        validate_conf(config, "idpname")
        validate_conf(config, "bucketname")
        validate_conf(config, "obsendpoint")
        validate_conf(config, "prefix")
        validate_conf(config, "maxkeys")
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
    # Initialize Parameters
    ProxyHost = None
    ProxyPort = None
    Prefix = None
    LastMarker = None
    # Read Parameters passed by Splunk Configuration
    config = get_config()
    Instance = config["name"]
    IdpName = config["idpname"]
    OBSEndpoint = config["obsendpoint"]
    BucketName = config["bucketname"]
    Prefix = config["prefix"]
    MaxKeys = config["maxkeys"]
    UserName = config["username"]
    UserPass = config["userpass"]

    # Testing Variables
    Instance = "CTStrace"
    IdpName = "myidp"
    OBSEndpoint = "obs.eu-de.otc.t-systems.com"
    BucketName = "obs-robert"
    Prefix = "CTS"
    MaxKeys = "500"
    UserName = "robert"
    UserPass = "password"

    
    # # Setup Checkpoint file name based on Instance name. We ae parsing the name passed by Splunk
    slist = Instance.split("//")
    InstanceName = slist[1]
    CheckPoint = os.path.join(config["checkpoint_dir"], InstanceName +".checkpoint")
    

    # Authenticate with IdP Initiated Federation and return Token (Powershell Script)
    TokenID = get_token(UserName, UserPass)

    # Get Temporary AK/SK from IAM for Federated User
    AK, SK, TokenID = get_ak(TokenID)

    # Constructs a obs client instance with your account for accessing OBS
    # https://docs.otc.t-systems.com/en-us/sdk_python_api/obs/en-us_topic_0080493206.html
    obsClient = ObsClient(access_key_id=AK, secret_access_key=SK, security_token=TokenID,server=OBSEndpoint, proxy_host=ProxyHost, proxy_port=ProxyPort)
  
    # We check if the last run saved the checkpoint object so that we don't process already processed logs.
    if os.path.exists(CheckPoint):
        if os.path.getsize(CheckPoint):
            fo = open(CheckPoint, "r+" )
            LastMarker = fo.readline()
            fo.close()

    while True:
        # Start Processing Logs using the listobjects function defined above. This may cycle multiple times of more than maxkey returned.
        FinalMarker, FinalMarkerTag = processlogs(obsClient, prefix=Prefix, marker=LastMarker, max_keys=MaxKeys, source=InstanceName)
        if FinalMarkerTag is None:
            fo = open(CheckPoint, "w")
            fo.write(FinalMarker)
            fo.close()
            break
        LastMarker = FinalMarker

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