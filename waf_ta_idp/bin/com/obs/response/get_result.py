#!/usr/bin/python
# -*- coding:utf-8 -*-

import re
import os
import traceback
import threading
import time
import xml.etree.ElementTree as ET
from com.obs.log.log_client import WARNING, ERROR, DEBUG
from com.obs.log.Log import LOG
from com.obs.utils import common_util
from com.obs.utils import convert_util
from com.obs.models.base_model import BaseModel, BASESTRING, IS_PYTHON2, IS_WINDOWS
from com.obs.response.get_object_response import ObjectStream, ResponseWrapper


class RedirectException(Exception):
    pass

class GetResult(BaseModel):

    CONTEXT = threading.local()

    CONTEXT.location = None

    PATTERN = re.compile('xmlns="http.*?"')

    allowedAttr = {'status': int, 'reason':BASESTRING, 'errorCode': BASESTRING, 'errorMessage': BASESTRING,
                   'body': object, 'requestId': BASESTRING, 'hostId': BASESTRING, 'resource': BASESTRING, 'header':list}

    def __init__(self, code=None, message=None, status=None, reason=None, body=None, requestId=None, hostId=None, resource=None, header=None):
        self.status = status
        self.reason = reason
        self.errorCode = code
        self.errorMessage = message
        self.body = body
        self.requestId = requestId
        self.hostId = hostId
        self.resource = resource
        self.header = header

    @classmethod
    def getNoneResult(cls, message='None Result'):
        return GetResult(code=-1, message=message, status=-1)

    @classmethod
    def get_data(cls, result, downloadPath, chuckSize):
        origin_file_path = downloadPath
        if IS_WINDOWS:
            downloadPath = common_util.safe_trans_to_gb2312(downloadPath)
        pathDir = os.path.dirname(downloadPath)
        if not os.path.exists(pathDir):
            os.makedirs(pathDir, 0o755)
        with open(downloadPath, 'wb') as f:
            while True:
                chunk = result.read(chuckSize)
                if not chunk:
                    break
                f.write(chunk)
        return origin_file_path

    @classmethod
    def parse_content(cls, conn, objectKey, downloadPath=None, chuckSize=65536, loadStreamInMemory=False, connHolder=None):
        if not conn:
            return cls.getNoneResult('connection is null')
        closeConn = True
        result = None
        try:
            result = conn.getresponse()
            if not result:
                return cls.getNoneResult('response is null')

            if connHolder and hasattr(connHolder, 'createTimeStamp'):
                connHolder.createTimeStamp = time.time()

            if not common_util.toInt(result.status) < 300:
                return cls.__parse_xml(result)

            if loadStreamInMemory:
                LOG(DEBUG, 'loadStreamInMemory is True, read stream into memory')
                buf = None
                while True:
                    chunk = result.read(chuckSize)
                    if not chunk:
                        break
                    if buf is None:
                        buf = chunk
                    else:
                        buf += chunk
                body = ObjectStream(buffer=buf, size=common_util.toLong(len(buf)))
            elif downloadPath is None or common_util.toString(downloadPath).strip() == '':
                LOG(DEBUG, 'DownloadPath is null, return conn directly')
                closeConn = False
                body = ObjectStream(response=ResponseWrapper(conn, result, connHolder))
            else:
                objectKey = common_util.safe_encode(objectKey)
                downloadPath = common_util.safe_encode(downloadPath)
                file_path = cls.get_data(result, downloadPath, chuckSize)
                body = ObjectStream(url=common_util.toString(file_path))
                LOG(DEBUG, 'DownloadPath is ' + common_util.toString(file_path))

            status = common_util.toInt(result.status)
            reason = result.reason
            headers = dict(result.getheaders())
            header = cls.__parse_headers(headers)
            requestId = headers.get('x-amz-request-id')

            convert_util.parseGetObject(dict(header), body)
            return GetResult(status=status, reason=reason, header=header, body=body, requestId=requestId)
        except RedirectException as ex:
            raise ex
        except Exception as e:
            LOG(ERROR, traceback.format_exc())
            raise e
        finally:
            if closeConn:
                GetResult.doClose(result, conn, connHolder)

    @classmethod
    def __parse_headers(cls, headers):
        header = []
        for k, v in headers.items():
            k = common_util.toString(k).lower()
            flag = 0
            if k.startswith(common_util.METADATA_PREFIX):
                k = k[k.index(common_util.METADATA_PREFIX) + len(common_util.METADATA_PREFIX):]
                flag = 1
            elif k.startswith(common_util.AMAZON_HEADER_PREFIX):
                k = k[k.index(common_util.AMAZON_HEADER_PREFIX) + len(common_util.AMAZON_HEADER_PREFIX):]
                flag = 1
            elif k in common_util.ALLOWED_RESPONSE_HTTP_HEADER_METADATA_NAMES:
                flag = 1
            if flag:
                header.append((k, v))
        return header

    @classmethod
    def __parse_xml(cls, result, methodName=None, chuckSize=65536, readable=False):
        status = common_util.toInt(result.status)
        reason = result.reason
        code = None
        message = None
        body = None
        requestId = None
        hostId = None
        resource = None
        headers = dict(result.getheaders())
        xml = None
        while True:
            chunk = result.read(chuckSize)
            if not chunk:
                break
            xml = chunk if xml is None else xml + chunk
        
        if status == 307 and not readable and ('location' in headers or 'Location' in headers):
            location = headers.get('location')
            if location is None:
                location = headers.get('Location')
            LOG(WARNING, 'http code is %d, need to redirect to %s', status, location)
            cls.CONTEXT.location = location
            raise RedirectException('http code is {0}, need to redirect to {1}'.format(status, location))
        else:
            header = cls.__parse_headers(headers)
            if status < 300:
                if methodName is not None:
                    methodName = 'parse' + methodName[:1].upper() + methodName[1:]
                    parseMethod = getattr(convert_util, methodName)
                    if parseMethod is not None:
                        if xml:
                            xml = xml if IS_PYTHON2 else xml.decode('UTF-8')
                            LOG(DEBUG, 'recv Msg:%s', xml)
                            try:
                                search = cls.PATTERN.search(xml)
                                xml = xml if search is None else xml.replace(search.group(), '')
                                body = parseMethod(xml, dict(header))
                            except Exception as e:
                                LOG(ERROR, e)
                        else:
                            body = parseMethod(dict(header))
                requestId = headers.get('x-amz-request-id')
            elif xml:
                xml = xml if IS_PYTHON2 else xml.decode('UTF-8')
                try:
                    search = cls.PATTERN.search(xml)
                    xml = xml if search is None else xml.replace(search.group(), '')
                    root = ET.fromstring(xml)
                    code = root.find('./Code')
                    code = code.text if code is not None else None
                    message = root.find('./Message')
                    message = message.text if message is not None else None
                    requestId = root.find('./RequestId')
                    requestId = requestId.text if requestId is not None else None
                    hostId = root.find('./HostId')
                    hostId = hostId.text if hostId is not None else None
                    key = root.find('./Key')
                    bucket = root.find('./BucketName')
                    resource = bucket if bucket is not None else key
                    resource = resource.text if resource is not None else None
                except Exception as ee:
                    LOG(ERROR, common_util.toString(ee))
                    LOG(ERROR, traceback.format_exc())

        LOG(DEBUG, 'http response result:status:%d,reason:%s,code:%s,message:%s,headers:%s', status, reason, code,
            message, header)

        return GetResult(code=code, message=message, status=status, reason=reason, body=body, requestId=requestId, hostId=hostId, resource=resource, header=header)

    @classmethod
    def parse_xml(cls, conn, methodName=None, connHolder=None, readable=False):
        if not conn:
            return cls.getNoneResult('connection is null')
        result = None
        try:
            result = conn.getresponse()
            if not result:
                return cls.getNoneResult('response is null')
            return cls.__parse_xml(result, methodName, readable=readable)
        except RedirectException as ex:
            raise ex
        except Exception as e:
            LOG(ERROR, traceback.format_exc())
            raise e
        finally:
            GetResult.doClose(result, conn, connHolder)

    @staticmethod
    def doClose(result, conn, connHolder):
        common_util.doClose(result, conn, connHolder)

    @staticmethod
    def closeConn(conn, connHolder):
        common_util.closeConn(conn, connHolder)
