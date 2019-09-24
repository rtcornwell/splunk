#!/usr/bin/python
# -*- coding:utf-8 -*-
# Splunk Application to import Object Storage CTS Logs.
# Written for EY using the EY Powershell Authentication script for Federated users.
import sys
import time
import datetime
import urllib
import os
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
            <arg name="projectid">
                <title>ProjectID</title>
                <description>Enter the ProjectID where the WAF server is running.</description>
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
def get_token(UserName, UserPass, IdpName):

    PowerShellPath = r'C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe'
    # PowerShellCmd  = r'C:\\Program Files\\Splunk\\etc\\apps\\obs_ta_idp\\bin\\otc-get-token.ps1'
    PowerShellCmd  = r'C:\\Users\\rtcor\\.vscode\\PythonProjects\\Splunk\\waf_ta_idp\bin\\otc-get-token.ps1'
    p = subprocess.Popen([PowerShellPath,'-ExecutionPolicy','Bypass','-file',PowerShellCmd,UserName,UserPass,IdpName]
        ,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    TokenID, err = p.communicate()
    rc = p.returncode
    if(err):
        raise Exception('Error: ' + str(err))
    return TokenID.strip()

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
        validate_conf(config, "projectid")
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
    # Initialize Parameters (Proxy not Used in this script)
    ProxyHost = None
    ProxyPort = None
    ProxyUserName = None
    ProxyPassword = None
    Proxies = None
    VerifyCert=False
    ToTime = str(int(time.time())*1000)
    FromTime = str(int(time.time()-7200)*1000)
    # Read Parameters passed by Splunk Configuration
    # config = get_config()
    # Instance = config["name"]
    # IdpName = config["idpname"]
    # ProjectID = config["projectid"]
    # UserName = config["username"]
    # UserPass = config["userpass"]
    # CheckPoint_dir = config["checkpoint_dir"]
    Instance = "waf_at_idp//WafLogs"
    IdpName = "IDP"
    ProjectID = "bf74229f30c0421fae270386a43315ee"
    UserName = "robert"
    UserPass = "pass"
    CheckPoint_dir = "C:/temp"
    
              
    # # Setup Checkpoint file name based on Instance name. We ae parsing the name passed by Splunk
    slist = Instance.split("//")
    InstanceName = slist[1]
    CheckPoint = os.path.join(CheckPoint_dir, InstanceName +".checkpoint")
    

    # Authenticate with IdP Initiated Federation and return Token (Powershell Script)
    TokenID = get_token(UserName, UserPass, IdpName)
    # TokenID = "MIIGeAYJKoZIhvcNAQcCoIIGaTCCBmUCAQExDTALBglghkgBZQMEAgEwggRGBgkqhkiG9w0BBwGgggQ3BIIEM3sidG9rZW4iOnsiZXhwaXJlc19hdCI6IjIwMTktMDktMjVUMTc6MDg6MDEuMjY2MDAwWiIsIm1ldGhvZHMiOlsicGFzc3dvcmQiXSwiY2F0YWxvZyI6W10sInJvbGVzIjpbeyJuYW1lIjoidGVfYWdlbmN5IiwiaWQiOiI0MWNlNTg1N2M5NGM0Nzc1YjZjYzUzZDVmZWViYTQ0NSJ9LHsibmFtZSI6InRlX2FkbWluIiwiaWQiOiI2OTliZDYyY2RhMzA0ZDJjYWQwM2ZkMmZiMTkwYjhjZiJ9LHsibmFtZSI6InNkcnNfYWRtIiwiaWQiOiI1ZDNlMWYzYjQ1MmM0MTAwODY5MmE0ZWI5MDUzMTA5OSJ9LHsibmFtZSI6IndhZl9hZG0iLCJpZCI6IjZiZDk5Yzg5ZjNjNDQ4OThiNzkzYTk4ZDFkOWYyNjY2In0seyJuYW1lIjoiZG1zX2FkbSIsImlkIjoiNDFmZjZhNzc5ZmEwNGU1YmFhNzkxZTQ1YzM3ZjViYWIifSx7Im5hbWUiOiJzZXJ2ZXJfYWRtIiwiaWQiOiI1OThjYzIyMTgzN2I0ZGM0YjUyOTg2OTczYWVmM2QzZSJ9LHsibmFtZSI6InNtbl9hZG0iLCJpZCI6ImVhOWQ4NTYwYmQ2ZTRiYmVhZTJlYzEyNTY1YjQ0MmEwIn0seyJuYW1lIjoib3BfZ2F0ZWRfY2NlX3N3aXRjaCIsImlkIjoiMCJ9XSwicHJvamVjdCI6eyJkb21haW4iOnsieGRvbWFpbl90eXBlIjoiVFNJIiwibmFtZSI6Ik9UQzAwMDAwMDAwMDAxMDAwMDEwNTAxIiwiaWQiOiJhMDFhYWZjZjYzNzQ0ZDk4OGViZWYyYjFlMDRjNWMzNCIsInhkb21haW5faWQiOiIwMDAwMDAwMDAwMTAwMDAxMDUwMSJ9LCJuYW1lIjoiZXUtZGUiLCJpZCI6ImJmNzQyMjlmMzBjMDQyMWZhZTI3MDM4NmE0MzMxNWVlIn0sImlzc3VlZF9hdCI6IjIwMTktMDktMjRUMTc6MDg6MDEuMjY2MDAwWiIsInVzZXIiOnsiZG9tYWluIjp7Inhkb21haW5fdHlwZSI6IlRTSSIsIm5hbWUiOiJPVEMwMDAwMDAwMDAwMTAwMDAxMDUwMSIsImlkIjoiYTAxYWFmY2Y2Mzc0NGQ5ODhlYmVmMmIxZTA0YzVjMzQiLCJ4ZG9tYWluX2lkIjoiMDAwMDAwMDAwMDEwMDAwMTA1MDEifSwibmFtZSI6InJvYmVydGNvcm53ZWxsIiwicGFzc3dvcmRfZXhwaXJlc19hdCI6IjIwMjAtMDMtMDdUMTU6NDA6MTYuMDAwMDAwIiwiaWQiOiI2ZmU3NzY0YTRmZTM0ZjVmOTYzYTk4M2YxZmY4ZDI0YiJ9fX0xggIFMIICAQIBATBcMFcxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVVbnNldDEOMAwGA1UEBwwFVW5zZXQxDjAMBgNVBAoMBVVuc2V0MRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20CAQEwCwYJYIZIAWUDBAIBMA0GCSqGSIb3DQEBAQUABIIBgAcznk3jVXU1vvgP7ELh2QTjSlirOtZM5r+mzbLfuY9AA6uQQOESqhqKcyzTUln-gwkGBwvZMg1DtY4Wdtd8IM6ZqaxzTivcpyYlosgF4RP8AiGGPdDpkiC9G4JpuBKCJgYVNxjoY7KnjmMBYxLyQ6OHHR0siOXz428doyRkcXSBYAO1jv4u+My1iYTnrZCFaYwwumZfxVAkHW40osnl884DZ-VMyMXHWxoIr9hTo8ewvTa2iv-iegYU2uHgIdyis4FXilQvtkNWAJcUgb0bt8U7iz2u18zc-3Wf-n+Hj4TdbNJheyzhsiX7fgRD4mbGfoc8h+NkHP-PcSrDh4TZAMqvlCMwcLb2DFr+P2TcbVkHPs0py1Pf4oOT0r33VYKMsOOAaJK5gkPuHxG7K3LptGTvKNmo9WgFZtcU9iE9oRxzj8RFZocZnzS1KLXOMNpCzoCqqSqbvgjmyV5303904LeZc0sr1TtAUfUfFIDr55+VVQa4bkpz9icANcVxizzzHw=="
    # We check if the last run saved the checkpoint object so that we don't process already processed logs.
    if os.path.exists(CheckPoint):
        if os.path.getsize(CheckPoint):
            fo = open(CheckPoint, "r+" )
            FromTime = fo.readline()
            fo.close()

    parms = "from="+ FromTime + "&to="+ ToTime
    url = "https://waf.eu-de.otc.t-systems.com/v1/" + ProjectID +"/waf/event?"+ parms
    Header = dict()
    Header.setdefault("X-Auth-Token",TokenID)
    Header.setdefault("Content-type", "application/json;charset=utf8")
    resp = http_get(url, Header, verify=True, cert=None, proxies=None, cookies=None)
    if resp.status_code== 200:
       
        data = json.loads(resp.text)
    
        Events = data["items"]
        for Event in Events:
            init_stream()
            # Convert timestamp in event from millisecond posix to seconds possix
            Event['time'] = int(round(Event['time'] / 1000))
            #Send formatted event data to sysout (Splunk Indexer)
            send_event(json.dumps(Event), Event['time'], InstanceName) 
            fini_stream()      
    else: 
         logging.debug("get_ak: Error Retrievinbg Events: , errorCode:%s" % resp.status_code)
    fo = open(CheckPoint, "w")
    fo.write(ToTime)
    fo.close()
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