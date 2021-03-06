#!/usr/bin/python
# -*- coding:utf-8 -*-
import sys
import time
import os
from com.obs.client.obs_client import ObsClient
import gzip
import io
import xml.dom.minidom
import xml.sax.saxutils
import logging
import requests
import json
import re
from urllib import quote
from requests.cookies import merge_cookies
import urllib

#set up logging suitable for splunkd consumption
logging.root
logging.root.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.root.addHandler(handler)

# Setup the Scheme used for the Splunk Web Application Interface
SCHEME = """<scheme>
    <title>OTC Cloud Trace Log Processing with IdP Azure AD Authentication support</title>
    <description>Retrieve Open Telekom Cloud Logs from OBS, Authenticate with Federated Accounts</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>
    <endpoint>
        <args>
            <arg name="name">
                <title>Instance Name</title>
                <description>Provide a unique name for this Instance/Stanza. IE: Cloudtrace, VPCFlow</description>
            </arg>
            <arg name="idpname">
                <title>IDP Name</title>
                <description>Enter the name of the IDP Federated configuration to authenticate against</description>
            </arg>
            <arg name="obsendpoint">
                <title>OBS Endpoint</title>
                <description>Enter the Url for the OBS endpoint.</description>
            </arg>
            <arg name="bucketname">
                <title>Bucketname</title>
                <description>Enter the name of the Bucket on OBS configure in CTS Traker.</description>
            </arg>
            <arg name="logprefix">
                <title>CTS Prefix</title>
                <description>Enter the Prefix used in the CTS Traker</description>
            </arg>
            <arg name="username">
                <title>User Name</title>
                <description>Azure AD or Other user accounts</description>
            </arg>
            <arg name="userpass">
                <title>User password</title>
                <description>Azure AD or Other user accounts password</description>
            </arg>
             <arg name="maxkeys">
                <title>Max Keys</title>
                <description>Enter the Max Keys parameter (100-1000). This is a tuning parameter for OBS Client</description>
            </arg>
      </args>
    </endpoint>
</scheme>
"""

def http_request(IAMurl, method, header, body=None, request_verify=True, request_cert=None, proxies=None, cookies=None):
    if body != None and type(body) != str:
        body = str(body)

    if header != None and type(header) != dict: header = json.loads(header)

    if header == None:  header = dict()

    header.setdefault("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36")
    resp = requests.request(method, IAMurl, data=body, headers=header, verify=request_verify, cert=request_cert, proxies=proxies, cookies=cookies, allow_redirects=False, timeout=600)
    return resp

def http_post(IAMurl, headers, data, verify=True, cert=None, proxies=None, cookies=None):

    response = http_request(IAMurl, "post", headers, body=data, request_verify=verify, request_cert=cert, proxies=proxies, cookies=cookies)
    return response

def http_get(IAMurl, headers, verify=True, cert=None, proxies=None, cookies=None):
    
    response = http_request(IAMurl, "get", headers, request_verify=verify, request_cert=cert, proxies=proxies, cookies=cookies)
    return response

# Function to authenticate with Azure SSO and return authentication Token
def get_token(IAMurl, UserName, UserPass):
    proxies = None
    # These urls may need to be customized depending if you are using standard Azure SSO or customized.
    getCredentialUrl = "https://login.microsoftonline.com/common/GetCredentialType?mkt=zh-CN"
    passwordUrl = "https://login.live.com/ppsecure/post.srf"
    authUrl = "https://login.microsoftonline.com/common/federation/oauth2"
    microUrl = "https://login.microsoftonline.com"

    encodeUserName = quote(UserName)
    iamResult = http_get(IAMurl, None, proxies=proxies)
    
    imaLocationUrl = iamResult.headers.get("Location")
    result = http_get(imaLocationUrl, None, proxies=proxies)
    if result.status_code!= 200:
        logging.debug("Error on First IamUrl Call: , errorCode:%s" % result.status_code)
        sys.exit(2)
    responseHeader = result.headers
    UserNameGetUrl = result.request.url
    cookies = result.cookies
    microsoftMatchPattern = re.compile("//<!\\[CDATA\\[[\\s]+\\$Config=(.*);[\\s]+//\\]\\]>")
    microsoftMatch = microsoftMatchPattern.findall(result.text.encode("utf-8"))
    microsoftMatchJson = json.loads(microsoftMatch[0])
    UserNamePostHeader = dict()
    UserNamePostHeader.setdefault("hpgrequestid", responseHeader.get("x-ms-request-id"))
    UserNamePostHeader.setdefault("Origin", microUrl)
    UserNamePostHeader.setdefault("canary", microsoftMatchJson.get("apiCanary"))
    UserNamePostHeader.setdefault("client-request-id", microsoftMatchJson.get("correlationId"))
    UserNamePostHeader.setdefault("Content-type", "application/json; charset=UTF-8")
    UserNamePostHeader.setdefault("hpgid", str(microsoftMatchJson.get("hpgid")))
    UserNamePostHeader.setdefault("hpgact", str(microsoftMatchJson.get("hpgact")))
    UserNamePostHeader.setdefault("Referer", UserNameGetUrl)
    UserNamePostHeader.setdefault("Accept", "application/json")
    mircroUrlPost = microsoftMatchJson.get("urlPost")
    bodyGetCredentialType = "{\"UserName\": \"%s\",\"isOtherIdpSupported\": true,\"checkPhones\": false,\"isRemoteNGCSupported\": true,\"isCookieBannerShown\": false,\"isFidoSupported\": false,\"originalRequest\": \"%s\",\"country\":\"DE\",\"forceotclogin\": false,\"flowToken\": \"%s\"}" % (
        encodeUserName, microsoftMatchJson.get("sCtx"), microsoftMatchJson.get("sFT"))

    credentialResponse = http_post(getCredentialUrl, UserNamePostHeader, bodyGetCredentialType, proxies=proxies, cookies=result.cookies)
    if credentialResponse.status_code!= 200:
        logging.debug("Error on credential response: , errorCode:%s" % credentialResponse.status_code)
        sys.exit(2)
    merge_cookies(cookies, credentialResponse.cookies)

    hpgRequestId = None
    sCtx = None
    canary = None
    sFT = None
    kmsiRequestCookies = None

    mircroRequestHeader = dict()
    mircroRequestHeader.setdefault("Origin", microUrl)
    mircroRequestHeader.setdefault("Content-type", "application/x-www-form-urlencoded")
    mircroRequestHeader.setdefault("Referer", UserNameGetUrl)
    mircroRequestHeader.setdefault("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3")
    mircroRequestBody = "i13=0&login=%s&loginfmt=%s&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd=%s&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=%s&ctx=%s&hpgrequestid=%s&flowToken=%s&PPSX=&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&i2=1&i17=&i18=&i19=15193" % (
        encodeUserName, encodeUserName, quote(UserPass), quote(microsoftMatchJson.get("canary")), microsoftMatchJson.get("sCtx"), responseHeader.get("x-ms-request-id"), microsoftMatchJson.get("sFT"))
    mircroResponse = http_post(mircroUrlPost, mircroRequestHeader, mircroRequestBody, proxies=proxies, cookies=cookies)
    mircroResponseCompile = re.compile("//<!\\[CDATA\\[[\\s]+\\$Config=(.*);[\\s]+//\\]\\]>")
    mircroResponseMatcher = mircroResponseCompile.findall(mircroResponse.text)
    mircroResponseObject = json.loads(mircroResponseMatcher[0])
    hpgRequestId = quote(mircroResponse.headers.get("x-ms-request-id"))
    sCtx = quote(mircroResponseObject.get("sCtx"))
    canary = quote(mircroResponseObject.get("canary"))
    sFT = quote(mircroResponseObject.get("sFT"))
    kmsiRequestCookies = merge_cookies(mircroResponse.cookies, cookies)

    kmsiRequestBody = "LoginOptions=1&ctx=%s&hpgrequestid=%s&flowToken=%s&canary=%s&i2=&i17=&i18=&i19=1784" % (sCtx, hpgRequestId, sFT, canary)
    kmsiHeader = dict()
    kmsiHeader.setdefault("Upgrade-Insecure-Requests", "1")
    kmsiHeader.setdefault("Origin", "https://login.microsoftonline.com")
    kmsiHeader.setdefault("Accept", "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2")
    kmsiHeader.setdefault("Referer", authUrl)
    kmsiHeader.setdefault("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

    kmsiResponse = http_post("https://login.microsoftonline.com/kmsi", kmsiHeader, kmsiRequestBody, proxies=proxies, cookies=kmsiRequestCookies)
    if kmsiResponse.status_code!= 302:
        logging.debug("Error in KMSI Response: , errorCode:%s" % kmsiResponse.status_code)
        sys.exit(2)
    sAMLResponseCompile = re.compile("name=\"SAMLResponse\"[\\s]+value=\"([\S]*)\"")
    relayStateCompile = re.compile("name=\"RelayState\"[\\s]+value=\"([\S]*)\"")
    sAMLResponse = sAMLResponseCompile.findall(kmsiResponse.text)[0]
    relayState = relayStateCompile.findall(kmsiResponse.text)[0]
    iamPostResponse = http_post("https://iam.eu-de.otc.t-systems.com/v3-ext/auth/OS-FEDERATION/SSO/SAML2/POST", kmsiHeader, "SAMLResponse=%s&RelayState=%s" % (quote(sAMLResponse), relayState), proxies=proxies)
    if iamPostResponse.status_code!= 201:
        logging.debug("Error in KMSI Response: , errorCode:%s" % iamPostResponse.status_code)
        sys.exit(2)
    iamPostLocationResponse = http_get(iamPostResponse.headers.get("Location"), None, proxies=proxies, cookies=iamPostResponse.cookies)
    if iamPostLocationResponse.status_code!= 201:
        logging.debug("Error in KMSI Response: , errorCode:%s" % iamPostLocationResponse.status_code)
        sys.exit(2)
    TokenID = iamPostLocationResponse.headers.get("X-Subject-Token")
    return TokenID

# Function to request temporary AK/SK and security key https://docs.otc.t-systems.com/en-us/api/iam/en-us_topic_0097949518.html
def get_ak(TokenID,Proxies=None, Verify=False):
    url = "https://iam.eu-de.otc.t-systems.com/v3.0/OS-CREDENTIAL/securitytokens"
    body = '{\"auth\":{\"identity\":{\"methods\": [\"token\"],\"token\":{\"id\": \"'+ TokenID.strip() +'\",\"duration-seconds\": \"900\"}}}}'
    Header = dict()
    Header.setdefault("Content-type", "application/json;charset=utf8")
    resp = requests.request('post', url, data=body, headers=Header, verify=Verify, cert=None, proxies=Proxies, cookies=None, allow_redirects=False, timeout=600)
    if resp.status_code!= 201:
        logging.debug("get_ak: Error Retrievinbg Temp AK/SK: , errorCode:%s" % resp.status_code)
        sys.exit(2)
    else: 
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
def processlogs(obsClient, BucketName, Bucket_folder, CheckPoint, prefix=None, marker=None, max_keys=None, source=None):
    resp_list = obsClient.listObjects(BucketName, marker=marker, max_keys=max_keys, prefix=Bucket_folder)
    if resp_list.status < 300:
        if resp_list.body.contents:
            for content in resp_list.body.contents:
                objectList = content.key.split('/')
                objectKey = objectList[len(objectList)-1]
                #Only process Logs that match the prefix passed and is a log file.
                if content.key.endswith('.gz') and objectKey.startswith(prefix):
                    resp_get = obsClient.getObject(BucketName,content.key, loadStreamInMemory=True)
                    if resp_get.status < 300 :
                        init_stream()
                        StreamData = read_gz_file(resp_get.body.buffer)
                        Events = json.loads(StreamData)
                        # Parse individual events from json Data (trace events) and send event to splunk indexer.
                        # https://docs.otc.t-systems.com/en-us/usermanual/cts/en-us_topic_0030598500.html
                        # Each log may contain one or many events so we want to parse each event and process each individually.
                        for Event in Events:
                            # Test if JSON Object is returned (List) or a Json String. Convert string to list
                            if isinstance(Event,str):
                                Event_dict = json.loads(Event)
                            else:
                                Event_dict = Event
                            # Convert timestamp in event from millisecond posix to seconds possix
                            Event_dict['time'] = int(round(Event_dict['time'] / 1000))
                            if 'record_time' in Event_dict: Event_dict['record_time'] = int(round(Event_dict['record_time'] / 1000))
                            #Send formatted event data to sysout (Splunk Indexer)
                            send_event(json.dumps(Event_dict), Event_dict['time'], source) 
                        fini_stream()
                        sys.stdout.flush()
                        fo = open(CheckPoint, "w")
                        fo.write(content.key)
                        fo.close()
                    else:
                        logging.debug("ProcessLogs: Error Accessing file: "+content.key+" Errocode: %s" , resp_get.returncode)
                        sys.exit(2)
                else:
                    logging.info("ProcessLogs: Skipping File that is not a matching Log File: %s" , content.key)
                 
            return content.key, resp_list.body.next_marker
        else:
            return marker, None
    else:
        logging.debug("Processlogs: Error Accessing OBS Bucket " + BucketName + ",errorCode:%s", resp_list.status)
        logging.debug('ProcessLogs: Error Message:%s', resp_list.errorMessage)
        return None, None

def validate_conf(config, key):
    if key not in config:
        logging.debug('PInvalid configuration received from Splunk: key %s is missing.', key)
        sys.exit(1)

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
            logging.debug('Invalid configuration received from Splunk')
            sys.exit(1)

        # just some validation: make sure these keys are present (required)
        validate_conf(config, "name")
        validate_conf(config, "idpname")
        validate_conf(config, "obsendpoint")
        validate_conf(config, "bucketname")
        validate_conf(config, "logprefix")
        validate_conf(config, "username")
        validate_conf(config, "userpass")
        validate_conf(config, "maxkeys")
        validate_conf(config, "checkpoint_dir")
            
    return config

def do_scheme():
    print (SCHEME)

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
    print ("usage: [--scheme|--validate-arguments]")
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
    LastMarker = None
    FinalMarker = None
    Prefix = None

   # Read Parameters passed by Splunk Configuration
    config = get_config()
    Instance = config["name"]
    IdpName = config["idpname"]
    OBSEndpoint = config["obsendpoint"]
    BucketName = config["bucketname"]
    Prefix = config["logprefix"]
    UserName = config["username"]
    UserPass = config["userpass"]
    MaxKeys = config["maxkeys"]
    CheckPoint_dir = config["checkpoint_dir"]

    # # Setup Checkpoint file name based on Instance name. We ae parsing the name passed by Splunk
    slist = Instance.split("//")
    InstanceName = slist[1]
    CheckPoint = os.path.join(CheckPoint_dir, InstanceName +".checkpoint")
    
    # Authenticate with IdP Initiated Federation and return Token (Powershell Script)
    TokenID = get_token(UserName, UserPass,IdpName)

    # Get Temporary AK/SK from IAM for Federated User
    AK, SK, TokenID = get_ak(TokenID,Proxies,VerifyCert)

    # Constructs a obs client instance with your account for accessing OBS
    # https://docs.otc.t-systems.com/en-us/sdk_python_api/obs/en-us_topic_0080493206.html
    obsClient = ObsClient(
        access_key_id=AK, 
        secret_access_key=SK, 
        security_token=TokenID,
        server=OBSEndpoint, 
        proxy_host=ProxyHost, 
        proxy_port=ProxyPort,
        proxy_username=ProxyUserName,
        proxy_password=ProxyPassword
    )
  
    # We check if the last run saved the checkpoint object so that we don't process already processed logs.
    if os.path.exists(CheckPoint):
        if os.path.getsize(CheckPoint):
            fo = open(CheckPoint, "r+" )
            LastMarker = fo.readline()
            fo.close()

    while True:
        # Start Processing Logs using the listobjects function defined above. This may cycle multiple times of more than maxkey returned.
        FinalMarker, FinalMarkerTag = processlogs(obsClient, BucketName, CheckPoint, prefix=Prefix, marker=LastMarker, max_keys=MaxKeys, source=InstanceName)
        if FinalMarkerTag is None:
            obsClient.close()
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