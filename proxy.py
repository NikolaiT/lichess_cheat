#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    
    HTTP Proxy Server in Python with explicit WebSocket support.
    
    :copyright: (c) 2013 by Abhinav Singh.
    :license: BSD, see LICENSE for more details.

    Added WebSocket support to modify and change WebSocket messages on Summer 2015.
    The original source code may be found on:

    https://github.com/abhinavsingh/proxy.py
"""
VERSION = (0, 3)
__version__ = '.'.join(map(str, VERSION[0:2]))
__description__ = 'HTTP Proxy Server in Python with WebSocket support'
__author__ = 'Nikolai Tschacher'
__author_email__ = 'contact@incolumitas.com'
__homepage__ = 'https://github.com/NikolaiT/proxy.py'
__license__ = 'BSD'

import sys
import multiprocessing
import datetime
import argparse
import logging
import socket
import select
import struct
import pprint
import json
import hashlib
import base64

logger = logging.getLogger(__name__)

# True if we are running on Python 3.
PY3 = sys.version_info[0] == 3

if PY3:
    text_type = str
    binary_type = bytes
    from urllib import parse as urlparse
else:
    text_type = unicode
    binary_type = str
    import urlparse


def text_(s, encoding='utf-8', errors='strict'):
    """ If ``s`` is an instance of ``binary_type``, return
    ``s.decode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, binary_type):
        return s.decode(encoding, errors)
    return s  # pragma: no cover


def bytes_(s, encoding='utf-8', errors='strict'):
    """ If ``s`` is an instance of ``text_type``, return
    ``s.encode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, text_type):  # pragma: no cover
        return s.encode(encoding, errors)
    return s

version = bytes_(__version__)

CRLF, COLON, SP = b'\r\n', b':', b' '

HTTP_REQUEST_PARSER = 1
HTTP_RESPONSE_PARSER = 2

HTTP_PARSER_STATE_INITIALIZED = 1
HTTP_PARSER_STATE_LINE_RCVD = 2
HTTP_PARSER_STATE_RCVING_HEADERS = 3
HTTP_PARSER_STATE_HEADERS_COMPLETE = 4
HTTP_PARSER_STATE_RCVING_BODY = 5
HTTP_PARSER_STATE_COMPLETE = 6

CHUNK_PARSER_STATE_WAITING_FOR_SIZE = 1
CHUNK_PARSER_STATE_WAITING_FOR_DATA = 2
CHUNK_PARSER_STATE_COMPLETE = 3


### Start modificiations by Nikolai Tschacher

class WebSocketFrame(object):
    """
    Some code taken and modified from 
    http://www.cs.rpi.edu/~goldsd/docs/spring2012-csci4220/websocket-py.txt
    """

    OPCODES = {
        0: 'CONTINUATION_FRAME',
        1: 'TEXT_FRAME',
        2: 'BINARY_FRAME',
        8: 'CONNECTION_CLOSE',
        9: 'PING_FRAME',
        0xA: 'PONG_FRAME', 
    }

    GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

    def __init__(self):
        self.fin = None
        self.opcode = None
        self.mask = 0
        self.masking_key = ''
        self.payload_length = None
        self.payload = ''
        self.unmasked_payload = ''

    def info(self):
        print(self)

    def get_frame_meta_data(self):
        return 'WebSocket Frame: fin = {}, opcode = {}, mask = {}, masking_key: {}, payload_length = {}'.format(
            self.fin, self.OPCODES.get(self.opcode, 'INVALID'), self.mask, self.masking_key, self.payload_length)

    def __str__(self):
        message = self.get_frame_meta_data()
        
        message += 'Payload:'
        try:
            nice = json.loads(self.unmasked_payload)            
            message += nice
        except:
            message += self.unmasked_payload
        message += '\n'

        return message

    def update_frame(self, new_unmasked_payload):
        """
        This method rebuilds the WebSocket frame with the new payload.
        """
        if len(self.unmasked_payload) == len(new_unmasked_payload):
            self.payload = WebSocketFrame.mask_payload(new_unmasked_payload, self.masking_key)
            self.unmasked_payload = new_unmasked_payload
        else:
            raise NotImplementedError('Create static build method for websockets.')

    def to_bytes(self):
        message = ''
        # always send an entire message as one frame (fin)
        b1 = 0x80
        b1 |= self.opcode

        message += chr(b1)

        # maybe mask frame
        b2 = self.mask << 7

        length = len(self.payload)

        if length < 126:
            b2 |= length
            message += chr(b2)
        elif length < (2 ** 16) - 1:
            b2 |= 126
            message += chr(b2)
            l = struct.pack("!H", length)
            message += l
        else:
            l = struct.pack("!Q", length)
            b2 |= 127
            message += chr(b2)
            message += l

        if self.mask == 1:
            message += self.masking_key

        message += self.payload

        return message


    @staticmethod
    def mask_payload(payload, mask):
        return ''.join([chr(ord(b) ^ ord(mask[i % 4])) for i, b in enumerate(payload)])


    @staticmethod
    def calculate_server_accept_header(sec_websocket_key):
        return base64.b64encode(hashlib.sha1((sec_websocket_key + WebSocketFrame.GUID).strip()).digest())


    @staticmethod
    def from_bytes(s):
        f = WebSocketFrame()

        if len(s) > 2:
            payload_start = 2
            f.fin = ord(s[0]) & 0x1
            f.opcode = ord(s[0]) & 0xF
            f.mask = ord(s[1]) & 0x1

            # the payload length has either 7 bits, 2 bytes, or
            # 8 bytes bitlength.
            f.payload_length = ord(s[1]) & 0xFE

            if f.payload_length == 126:
                f.payload_length, = struct.unpack("!H", s[2:4])
                payload_start += 2
            elif f.payload_length == 127:
                f.payload_length, = struct.unpack("!Q", s[2:10])
                payload_start += 8

            if f.mask == 1:
                # masking key, if present, starts right after the payload length
                f.masking_key = s[payload_start:payload_start+4]
                payload_start += 4

            f.payload = s[payload_start:f.payload_length+payload_start]

            if f.mask == 1:
                f.unmasked_payload = WebSocketFrame.mask_payload(f.payload, f.masking_key)
            else:
                f.unmasked_payload = f.payload

        return f


class WebSocketProxy(object):
    """May be used to manipulate web sockets communication.

    There are several points where the protocol logic can be altered:

        1. Initial handshake from client to server.
        2. Handshake response from server to client.
        3. Outgoing WebSocket messages.
        4. Incoming WebSocket messages.

    You can register a plugin by setting the plugin variable.
    """
    plugin = None

    @staticmethod
    def on_client_handshake(request):
        """
        You may modify the initial client handshake
        WebSocket request here. request is of type HttpParser.
        """
        if WebSocketProxy.plugin and hasattr(WebSocketProxy.plugin, 'on_client_handshake'):
            retval = WebSocketProxy.plugin.on_client_handshake(request)
            if retval:
                return retval

        return request

    @staticmethod
    def on_server_handshake(response):
        """
        You may also modify the server WebSocket response here.
        """
        if WebSocketProxy.plugin and hasattr(WebSocketProxy.plugin, 'on_server_handshake'):
            retval = WebSocketProxy.plugin.on_server_handshake(response)
            if retval:
                return retval

        return response

    @staticmethod
    def on_send_message(data):
        """
        The first plugin that modifies a outgoing
        message will alter the message.
        """
        frame = WebSocketFrame.from_bytes(data)

        logger.debug(frame.get_frame_meta_data())

        if WebSocketProxy.plugin and hasattr(WebSocketProxy.plugin, 'on_send_message'):
            retval = WebSocketProxy.plugin.on_send_message(frame, data)
            if retval:
                return retval

        return data

    @staticmethod
    def on_receive_message(data):
        """
        The first plugin that changes the received message
        will return the modified message.
        """
        frame = WebSocketFrame.from_bytes(data)

        logger.debug(frame.get_frame_meta_data())

        if WebSocketProxy.plugin and hasattr(WebSocketProxy.plugin, 'on_receive_message'):
            retval = WebSocketProxy.plugin.on_receive_message(frame)
            if retval:
                return retval

        return data

    @staticmethod
    def on_closing_handshake(data):
        """
        Either peer can send a control frame with data containing a specified
        control sequence to begin the closing handshake.
        """
        if WebSocketProxy.plugin and hasattr(WebSocketProxy.plugin, 'on_closing_handshake'):
            retval = WebSocketProxy.plugin.on_closing_handshake(data)
            if retval:
                return retval

        return data


class HttpProxy(object):
    """May be used to deal with HTTP Request/Response pairs.

    request and response objects are of type HttpParser.


    Always return the raw message when the modification is done.
    """

    plugin = None

    @staticmethod
    def on_request(request):
        """request is of type HttpParser.

        The plugin MUST return a request object.
        """
        if HttpProxy.plugin and hasattr(HttpProxy.plugin, 'on_request'):
            if request.successfully_parsed():
                retval = HttpProxy.plugin.on_request(request)
                if retval:
                    return retval

        return request


    @staticmethod
    def await_parsed_response(request):
        """The proxy will only parse the response if this method returns false"""

        if HttpProxy.plugin and hasattr(HttpProxy.plugin, 'await_parsed_response'):
            if request.successfully_parsed():
                return HttpProxy.plugin.await_parsed_response(request)

        return False

    @staticmethod
    def on_response(request, response):
        """request and response are of type HTTPParser.

        The plugin MUST return a response object.
        """
        if HttpProxy.plugin and hasattr(HttpProxy.plugin, 'on_response'):
            if request.successfully_parsed() and response.successfully_parsed():
                retval = HttpProxy.plugin.on_response(request, response)
                if retval:
                    return retval

        return response

### End modificiations by Nikolai Tschacher


class ChunkParser(object):
    """HTTP chunked encoding response parser."""
    
    def __init__(self):
        self.state = CHUNK_PARSER_STATE_WAITING_FOR_SIZE
        self.body = b''
        self.chunk = b''
        self.size = None
    
    def parse(self, data):
        more = True if len(data) > 0 else False
        while more: more, data = self.process(data)
    
    def process(self, data):
        if self.state == CHUNK_PARSER_STATE_WAITING_FOR_SIZE:
            line, data = HttpParser.split(data)
            self.size = int(line, 16)
            self.state = CHUNK_PARSER_STATE_WAITING_FOR_DATA
        elif self.state == CHUNK_PARSER_STATE_WAITING_FOR_DATA:
            remaining = self.size - len(self.chunk)
            self.chunk += data[:remaining]
            data = data[remaining:]
            if len(self.chunk) == self.size:
                data = data[len(CRLF):]
                self.body += self.chunk
                if self.size == 0:
                    self.state = CHUNK_PARSER_STATE_COMPLETE
                else:
                    self.state = CHUNK_PARSER_STATE_WAITING_FOR_SIZE
                self.chunk = b''
                self.size = None
        return len(data) > 0, data

class HttpParser(object):
    """HTTP request/response parser."""
    
    def __init__(self, type=None):
        self.state = HTTP_PARSER_STATE_INITIALIZED
        self.type = type if type else HTTP_REQUEST_PARSER
        
        self.raw = b''
        self.buffer = b''
        
        self.headers = dict()
        self.body = None
        
        self.method = None
        self.url = None
        self.code = None
        self.reason = None
        self.version = None
        
        self.chunker = None
    
    def parse(self, data):
        self.raw += data
        data = self.buffer + data
        self.buffer = b''
        
        more = True if len(data) > 0 else False
        while more: 
            more, data = self.process(data)
        self.buffer = data
    
    def process(self, data):
        if self.state >= HTTP_PARSER_STATE_HEADERS_COMPLETE and \
        (self.method == b"POST" or self.type == HTTP_RESPONSE_PARSER):
            if not self.body:
                self.body = b''

            if b'content-length' in self.headers:
                self.state = HTTP_PARSER_STATE_RCVING_BODY
                self.body += data
                if len(self.body) >= int(self.headers[b'content-length'][1]):
                    self.state = HTTP_PARSER_STATE_COMPLETE
            elif b'transfer-encoding' in self.headers and self.headers[b'transfer-encoding'][1].lower() == b'chunked':
                if not self.chunker:
                    self.chunker = ChunkParser()
                self.chunker.parse(data)
                if self.chunker.state == CHUNK_PARSER_STATE_COMPLETE:
                    self.body = self.chunker.body
                    self.state = HTTP_PARSER_STATE_COMPLETE
            
            return False, b''
        
        line, data = HttpParser.split(data)
        if line == False: return line, data
        
        if self.state < HTTP_PARSER_STATE_LINE_RCVD:
            self.process_line(line)
        elif self.state < HTTP_PARSER_STATE_HEADERS_COMPLETE:
            self.process_header(line)
        
        if self.state == HTTP_PARSER_STATE_HEADERS_COMPLETE and \
        self.type == HTTP_REQUEST_PARSER and \
        not self.method == b"POST" and \
        self.raw.endswith(CRLF*2):
            self.state = HTTP_PARSER_STATE_COMPLETE
        
        return len(data) > 0, data
    
    def process_line(self, data):
        line = data.split(SP)
        try:
            if self.type == HTTP_REQUEST_PARSER:
                self.method = line[0].upper()
                self.url = urlparse.urlsplit(line[1])
                self.version = line[2]
            else:
                self.version = line[0]
                self.code = line[1]
                self.reason = b' '.join(line[2:])
        except IndexError as e:
            raise Exception('Index error with line: {}'.format(line))

        self.state = HTTP_PARSER_STATE_LINE_RCVD
    
    def process_header(self, data):
        if len(data) == 0:
            if self.state == HTTP_PARSER_STATE_RCVING_HEADERS:
                self.state = HTTP_PARSER_STATE_HEADERS_COMPLETE
            elif self.state == HTTP_PARSER_STATE_LINE_RCVD:
                self.state = HTTP_PARSER_STATE_RCVING_HEADERS
        else:
            self.state = HTTP_PARSER_STATE_RCVING_HEADERS
            parts = data.split(COLON)
            key = parts[0].strip()
            value = COLON.join(parts[1:]).strip()
            self.headers[key.lower()] = (key, value)

    def get_header(self, key):
        return self.headers.get(key, ('', ''))[1]

    def successfully_parsed(self):
        return self.state == HTTP_PARSER_STATE_COMPLETE
    
    def build_url(self):
        if not self.url:
            return b'/None'
        
        url = self.url.path
        if url == b'': url = b'/'
        if not self.url.query == b'': url += b'?' + self.url.query
        if not self.url.fragment == b'': url += b'#' + self.url.fragment
        return url
    
    def build_header(self, k, v):
        return k + b": " + v + CRLF
    
    def build(self, del_headers=None, add_headers=None):
        if self.type == HTTP_REQUEST_PARSER:
            req = b" ".join([self.method, self.build_url(), self.version])
        else:
            req = b" ".join([self.version, self.code, self.reason])

        req += CRLF
        
        if not del_headers: del_headers = []
        for k in self.headers:
            if not k in del_headers:
                req += self.build_header(self.headers[k][0], self.headers[k][1])
        
        if not add_headers: add_headers = []
        for k in add_headers:
            req += self.build_header(k[0], k[1])
        
        req += CRLF
        if self.body:
            req += self.body
        
        return req

    def __str__(self):
        if self.type == HTTP_REQUEST_PARSER:
            return '{} {} {}'.format(self.url, self.method, self.version)
        else:
            return '{} {} {}'.format(self.version, self.code, self.reason)

    @staticmethod
    def split(data):
        pos = data.find(CRLF)
        if pos == -1: return False, data
        line = data[:pos]
        data = data[pos+len(CRLF):]
        return line, data

class Connection(object):
    """TCP server/client connection abstraction."""
    
    def __init__(self, what):
        self.buffer = b''
        self.closed = False
        self.what = what # server or client
    
    def send(self, data):
        return self.conn.send(data)
    
    def recv(self, bytes=8192):
        try:
            data = self.conn.recv(bytes)

            if len(data) == 0:
                logger.debug('recvd 0 bytes from %s' % self.what)
                return None
            logger.debug('rcvd %d bytes from %s' % (len(data), self.what))
            return data
        except Exception as e:
            logger.exception('Exception while receiving from connection %s %r with reason %r' % (self.what, self.conn, e))
            return None
    
    def close(self):
        self.conn.close()
        self.closed = True
    
    def buffer_size(self):
        return len(self.buffer)
    
    def has_buffer(self):
        return self.buffer_size() > 0
    
    def queue(self, data):
        self.buffer += data
    
    def flush(self):
        sent = self.send(self.buffer)
        self.buffer = self.buffer[sent:]
        logger.debug('flushed %d bytes to %s' % (sent, self.what))

class Server(Connection):
    """Establish connection to destination server."""
    
    def __init__(self, host, port):
        super(Server, self).__init__(b'server')
        self.addr = (host, int(port))
    
    def connect(self):
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((self.addr[0], self.addr[1]))

class Client(Connection):
    """Accepted client connection."""
    
    def __init__(self, conn, addr):
        super(Client, self).__init__(b'client')
        self.conn = conn
        self.addr = addr

class ProxyError(Exception):
    pass

class ProxyConnectionFailed(ProxyError):
    
    def __init__(self, host, port, reason):
        self.host = host
        self.port = port
        self.reason = reason
    
    def __str__(self):
        return '<ProxyConnectionFailed - %s:%s - %s>' % (self.host, self.port, self.reason)

class Proxy(multiprocessing.Process):
    """HTTP proxy implementation.
    
    Accepts connection object and act as a proxy between client and server.

    Detects WebSocket handshakes and the messages in a websocket communication.
    """
    
    def __init__(self, client):
        super(Proxy, self).__init__()
        
        self.start_time = self._now()
        self.last_activity = self.start_time
        
        self.client = client
        self.server = None
        
        self.request = HttpParser()
        self.response = HttpParser(HTTP_RESPONSE_PARSER)
        
        self.connection_established_pkt = CRLF.join([
            b'HTTP/1.1 200 Connection established',
            b'Proxy-agent: proxy.py v' + version,
            CRLF
        ])

        # WebSocket related state information
        self.ws_client_handshake_received = False
        self.ws_server_response_received = False
        self.ws_secrect_correct_predicted = False
        self.ws_accept_header = ''
    
    def _now(self):
        return datetime.datetime.utcnow()
    
    def _inactive_for(self):
        return (self._now() - self.last_activity).seconds
    
    def _is_inactive(self):
        return self._inactive_for() > 30

    def ws_handshake_established(self):
        """
        Checks that the handshake was observed and that
        the handshake secret is correctly computed.
        """
        return self.ws_server_response_received and self.ws_client_handshake_received and self.ws_secrect_correct_predicted
    
    def _process_request(self, data):

        # check for ws connections
        if 'Sec-WebSocket-Version:' in data and 'Sec-WebSocket-Key:' in data:
            request = HttpParser()
            request.parse(data)
            WebSocketProxy.on_client_handshake(request)
            self.ws_client_handshake_received = True
            logger.debug('WebSocket client handshake received.')
            self.ws_accept_header = WebSocketFrame.calculate_server_accept_header(request.get_header('sec-websocket-key'))

        if self.ws_handshake_established():
            data = WebSocketProxy.on_send_message(data)
            self.server.queue(data)
            return

        # once we have connection to the server
        # we don't parse the http request packets
        # any further, instead just pipe incoming
        # data from client to server
        if self.server and not self.server.closed:
            self.server.queue(data)
            return
        
        # parse http request
        self.request.parse(data)
        
        # once http request parser has reached the state complete
        # we attempt to establish connection to destination server
        if self.request.state == HTTP_PARSER_STATE_COMPLETE:
            logger.debug('request parser is in state complete')

            if self.request.method == b"CONNECT":
                host, port = self.request.url.path.split(COLON)
            elif self.request.url:
                host, port = self.request.url.hostname, self.request.url.port if self.request.url.port else 80
            
            self.server = Server(host, port)
            try:
                logger.debug('connecting to server %s:%s' % (host, port))
                self.server.connect()
                logger.debug('connected to server %s:%s' % (host, port))
            except Exception as e:
                self.server.closed = True
                raise ProxyConnectionFailed(host, port, repr(e))
            
            # for http connect methods (https requests)
            # queue appropriate response for client 
            # notifying about established connection
            if self.request.method == b"CONNECT":
                self.client.queue(self.connection_established_pkt)
            # for usual http requests, re-build request packet
            # and queue for the server with appropriate headers
            else:
                self.request = HttpProxy.on_request(self.request)
                self.server.queue(self.request.build(
                    del_headers=[b'proxy-connection', b'connection', b'keep-alive'], 
                    add_headers=[(b'Connection', b'Close')]
                ))

    def _process_response(self, data):
        # parse incoming response packet
        # only for non-https requests
        if not self.request.method == b"CONNECT":
            self.response.parse(data)

        # check if the TCP stream is a WebSocket Upgrade connection
        if 'Sec-WebSocket-Accept:' in data and 'HTTP/1.1 101 Switching Protocols' in data:
            response = HttpParser(type=HTTP_RESPONSE_PARSER)
            response.parse(data)
            self.ws_server_response_received = True
            logger.debug('WebSocket server accept handshake received.')
            WebSocketProxy.on_server_handshake(response)
            if response.get_header('sec-websocket-accept') == self.ws_accept_header:
                self.ws_secrect_correct_predicted = True
            else:
                logger.info('WebSocket handshake failed: Sec-WebSocket-Accept not correctly predicted.')

        # if the websocket handshake was successfully established, we deal with ws messages
        if self.ws_handshake_established():
            data = WebSocketProxy.on_receive_message(data)
            self.client.queue(data)
            return

        if self.response.state == HTTP_PARSER_STATE_COMPLETE and HttpProxy.await_parsed_response(self.request):
            self.response = HttpProxy.on_response(self.request, self.response)
            self.client.queue(self.response.raw)

        # queue data for client
        if not HttpProxy.await_parsed_response(self.request):
            self.client.queue(data)
    
    def _access_log(self):
        host, port = self.server.addr if self.server else (None, None)
        if self.request.method == b"CONNECT":
            logger.info("%s:%s - %s %s:%s" % (self.client.addr[0], self.client.addr[1], self.request.method, host, port))
        elif self.request.method:
            logger.info("%s:%s - %s %s:%s%s - %s %s - %s bytes" % (self.client.addr[0], self.client.addr[1], self.request.method, host, port, self.request.build_url(), self.response.code, self.response.reason, len(self.response.raw)))
        
    def _get_waitable_lists(self):
        rlist, wlist, xlist = [self.client.conn], [], []
        logger.debug('*** watching client for read ready')

        if self.client.has_buffer():
            logger.debug('pending client buffer found, watching client for write ready')
            wlist.append(self.client.conn)
        
        if self.server and not self.server.closed:
            logger.debug('connection to server exists, watching server for read ready')
            rlist.append(self.server.conn)
        
        if self.server and not self.server.closed and self.server.has_buffer():
            logger.debug('connection to server exists and pending server buffer found, watching server for write ready')
            wlist.append(self.server.conn)
        
        return rlist, wlist, xlist
    
    def _process_wlist(self, w):
        if self.client.conn in w:
            logger.debug('client is ready for writes, flushing client buffer')
            self.client.flush()
        
        if self.server and not self.server.closed and self.server.conn in w:
            logger.debug('server is ready for writes, flushing server buffer')
            self.server.flush()
    
    def _process_rlist(self, r):
        if self.client.conn in r:
            logger.debug('client is ready for reads, reading')
            data = self.client.recv()
            self.last_activity = self._now()
            
            if not data:
                logger.debug('client closed connection, breaking')
                return True
            
            try:
                self._process_request(data)
            except ProxyConnectionFailed as e:
                logger.exception(e)
                self.client.queue(CRLF.join([
                    b'HTTP/1.1 502 Bad Gateway',
                    b'Proxy-agent: proxy.py v' + version,
                    b'Content-Length: 11',
                    b'Connection: close',
                    CRLF
                ]) + b'Bad Gateway')
                self.client.flush()
                return True
        
        if self.server and not self.server.closed and self.server.conn in r:
            logger.debug('server is ready for reads, reading')
            data = self.server.recv()
            self.last_activity = self._now()
            
            if not data:
                logger.debug('server closed connection')
                self.server.close()
            else:
                self._process_response(data)
        
        return False
    
    def _process(self):
        while True:
            rlist, wlist, xlist = self._get_waitable_lists()
            r, w, x = select.select(rlist, wlist, xlist, 1)
            
            self._process_wlist(w)
            if self._process_rlist(r):
                break
            
            if self.client.buffer_size() == 0:
                if self.response.state == HTTP_PARSER_STATE_COMPLETE:
                    logger.debug('client buffer is empty and response state is complete, breaking')
                    break
                
                if self._is_inactive():
                    logger.debug('client buffer is empty and maximum inactivity has reached, breaking')
                    break
    
    def run(self):
        logger.debug('Proxying connection %r at address %r' % (self.client.conn, self.client.addr))
        try:
            self._process()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.exception('Exception while handling connection %r with reason %r' % (self.client.conn, e))
        finally:
            logger.debug("closing client connection with pending client buffer size %d bytes" % self.client.buffer_size())
            self.client.close()
            if self.server:
                logger.debug("closed client connection with pending server buffer size %d bytes" % self.server.buffer_size())
            self._access_log()
            logger.debug('Closing proxy for connection %r at address %r' % (self.client.conn, self.client.addr))

class TCP(object):
    """TCP server implementation."""
    
    def __init__(self, hostname='127.0.0.1', port=8899, backlog=100):
        self.hostname = hostname
        self.port = port
        self.backlog = backlog
    
    def handle(self, client):
        raise NotImplementedError()
    
    def run(self):
        try:
            logger.info('Starting server on port %d' % self.port)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.hostname, self.port))
            self.socket.listen(self.backlog)
            while True:
                conn, addr = self.socket.accept()
                logger.debug('Accepted connection %r at address %r' % (conn, addr))
                client = Client(conn, addr)
                self.handle(client)
        except Exception as e:
            logger.exception('Exception while running the server %r' % e)
        finally:
            logger.info('Closing server socket')
            self.socket.close()

class HTTP(TCP):
    """HTTP proxy server implementation.
    
    Spawns new process to proxy accepted client connection.
    """
    
    def handle(self, client):
        proc = Proxy(client)
        proc.daemon = True
        proc.start()
        logger.debug('Started process %r to handle connection %r' % (proc, client.conn))

def main():
    parser = argparse.ArgumentParser(
        description='proxy.py v%s' % __version__,
        epilog='Having difficulty using proxy.py? Report at: %s/issues/new' % __homepage__
    )
    
    parser.add_argument('--hostname', default='127.0.0.1', help='Default: 127.0.0.1')
    parser.add_argument('--port', default='8899', help='Default: 8899')
    parser.add_argument('--log-level', default='INFO', help='DEBUG, INFO, WARNING, ERROR, CRITICAL')
    args = parser.parse_args()
    
    logging.basicConfig(level=getattr(logging, args.log_level), format='%(asctime)s - %(levelname)s - pid:%(process)d - %(message)s')
    
    hostname = args.hostname
    port = int(args.port)
    
    try:
        proxy = HTTP(hostname, port)
        proxy.run()
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
