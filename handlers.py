#!/usr/bin/python
# Copyright (c) 2015 Radoslav Gerganov
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
Handlers for ESXi hosts to handle handshakes
  and make dynamic connections based on request params
"""

import base64
import errno
import hashlib
import logging
import os
import random
import select
import six
import socket
import ssl
import sys
import time
import urlparse
import websockify

VMAD_OK = 200
VMAD_WELCOME = 220
VMAD_LOGINOK = 230
VMAD_NEEDPASSWD = 331
VMAD_USER_CMD = "USER"
VMAD_PASS_CMD = "PASS"
VMAD_THUMB_CMD = "THUMBPRINT"
VMAD_CONNECT_CMD = "CONNECT"

def expect(sock, code):
    line = sock.recv(1024)
    recv_code, msg = line.split()[0:2]
    if code != int(recv_code):
        raise Exception('Expected %d but received %d' % (code, recv_code))
    return msg


def handshake(host, port, ticket, cfg_file, thumbprint):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    expect(sock, VMAD_WELCOME)
    sock = ssl.wrap_socket(sock)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    cert = sock.getpeercert(binary_form=True)
    h = hashlib.sha1()
    h.update(cert)
    if thumbprint != h.hexdigest():
        raise Exception("Server thumbprint doesn't match")
    sock.write("%s %s\r\n" % (VMAD_USER_CMD, ticket))
    expect(sock, VMAD_NEEDPASSWD)
    sock.write("%s %s\r\n" % (VMAD_PASS_CMD, ticket))
    expect(sock, VMAD_LOGINOK)
    rand = os.urandom(12)
    rand = base64.b64encode(rand)
    sock.write("%s %s\r\n" % (VMAD_THUMB_CMD, rand))
    thumbprint2 = expect(sock, VMAD_OK)
    thumbprint2 = thumbprint2.replace(':', '').lower()
    sock.write("%s %s mks\r\n" % (VMAD_CONNECT_CMD, cfg_file))
    expect(sock, VMAD_OK)
    sock2 = ssl.wrap_socket(sock)
    cert2 = sock2.getpeercert(binary_form=True)
    h = hashlib.sha1()
    h.update(cert2)
    if thumbprint2 != h.hexdigest():
        raise Exception("Second thumbprint doesn't match")
    sock2.write(rand)
    return sock2

class ESXi5Handler(websockify.ProxyRequestHandler):

    def _handle_esx_init(self, tsock, ticket):
        """
        We need to handle some negotiation with
        noVNC since ESX doesn't
        """
        def log(msg, *args):
            self.log_message("(ticket %s) " + msg, *[ticket]+list(args))

        def check_close(closed):
            if closed:
                if self.verbose:
                    self.log_message("%s:%s: Client closed connection",
                                     self.server.target_host,
                                     self.server.target_port)
                raise self.CClose(closed['code'], closed['reason'])

        #RFB protocol
        version = "RFB 003.008"
        log("Sending version %s", version)
        self.send_frames([version+"\n",])
        agreed_version, closed = self.recv_frames()
        check_close(closed)
        agreed_version = agreed_version[0]
        log("Received version %s", agreed_version)
        if agreed_version != "RFB 003.008\n":
            if self.verbose:
                self.log_message("Client sent unsupported RFB version")
            raise self.CClose(1000, "Unsupported RFB version")

        #Security types
        log("Sending security types (None)")
        self.send_frames(["\x01\x01"])
        agreed_security_type, closed =  self.recv_frames()
        check_close(closed)
        agreed_security_type = agreed_security_type[0]
        log("Client security type is %s", agreed_security_type.encode('hex'))
        if agreed_security_type != b'\x01':
            if self.verbose:
                self.log_message("Client did not accept None security type")
            raise self.CClose(1000, "Server supports only None security type")

        #Security OK
        log("Sending OK security result")
        self.send_frames(["\x00\x00\00\x00"])
        shared_flag, closed = self.recv_frames()
        check_close(closed)
        shared_flag = shared_flag[0]
        log("Received shared flag %s", shared_flag.encode('hex'))
        check_close(closed)
        if shared_flag != b'\x01':
            if self.verbose:
                self.log_message("Client requested close other sessions. Which"
                                 "is not supported")
            raise self.CClose(1000, "Server supports only keeping connections")

        #Read and pass along the screen details
        log("Sending VM info")
        self.send_frames(tsock.recv(1024))

        log("init handling finished")

    def new_websocket_client(self):
        parse = urlparse.urlparse(self.path)
        query = parse.query
        args = urlparse.parse_qs(query)
        host = args.get("host", [""]).pop()
        port = args.get("port", [""]).pop()
        port = int(port)
        ticket = args.get("ticket", [""]).pop()
        cfg_file = args.get("cfgFile", [""]).pop()
        thumbprint = args.get("thumbprint", [""]).pop()
        thumbprint = thumbprint.replace(':', '').lower()

        tsock = handshake(host, port, ticket, cfg_file, thumbprint)
        self._handle_esx_init(tsock, ticket)
        #Disable Nagle's Algorithm
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        tsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.do_proxy(tsock)

class ESXi6Handler(websockify.ProxyRequestHandler):
    """
    Simple proxy that expects both sides to support websockets
    """

    def _recv_line(self, sock):
        """
        Receive from the socket one char at a time
        until we get to a new line

        Args:
          sock: The socket to receive from
        """
        line = []
        while True:
            character = sock.recv(1)
            line.append(character)
            if character == six.b("\n"):
                break
        return six.b("").join(line)

    def _read_headers(self, sock):
        """
        Read the headers line by line for the socket

        Args:
          sock: Socket to read headers from
        """
        status = None
        headers = {}

        while True:
            line = self._recv_line(sock)
            line = line.decode('utf-8').strip()
            if not line:
                break

            if not status:
                status_info = line.split(" ", 2)
                status = int(status_info[1])

            else:
                kv = line.split(":", 1)
                if len(kv) == 2:
                    field, value = kv
                    headers[field.lower()] = value.strip().lower()
                else:
                    raise Exception("Invalid header: %s" % kv)

        return status, headers

    def new_websocket_client(self):
        """
        Create a new socket to the target
        """
        parse = urlparse.urlparse(self.path)
        args = urlparse.parse_qs(parse.query)
        host = args.get("host", [""]).pop()
        port = 443
        ticket = args.get("ticket", [""]).pop()

        #Consider using the websocket_client code
        tsock = websockify.websocket.WebSocketServer.socket(
            host, port, connect=True, use_ssl=True, unix_socket=False)
        request = "GET /ticket/%s HTTP/1.1\r\n" % ticket
        upgrade = request + str(self.headers) + "\r\n"
        self.log_message("Upgrade headers:\n%s", upgrade)
        tsock.send(upgrade)
        status, headers = self._read_headers(tsock)
        if status != 101:
            raise Exception("Bad Response, %s, %s" % (status, headers))
        self.do_proxy(tsock)

    def do_proxy(self, target):
        """
        Handle the reading and writing of data being passed through
        the proxy

        Args:
          target: the websockify WebSocketServer socket of the target
            server
        """
        cqueue = []
        tqueue = []
        rlist = [self.request, target]

        #Disable Nagle's Algorithm for better responsiveness
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        target.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if self.server.heartbeat:
            now = time.time()
            self.heartbeat = now + self.server.heartbeat
        else:
            self.heartbeat = None

        while True:
            wlist = []

            if self.heartbeat is not None:
                now = time.time()
                if now > self.heartbeat:
                    self.heartbeat = now + self.server.heartbeat
                    #Currently, sending pings using the send_ping
                    # intertwines the pings with real data, causing
                    # a client error.
                    #TODO: Fix pings to make sure they are not
                    # in data.
                    # self.send_ping()

            if tqueue:
                wlist.append(target)
            if cqueue:
                wlist.append(self.request)

            try:
                ins, outs, excepts = select.select(rlist, wlist, [], 1)
            except (select.error, OSError):
                exc = sys.exc_info()[1]
                if hasattr(exc, 'errno'):
                    err = exc.errno
                else:
                    err = exc[0]

                if err != errno.EINTR:
                    raise
                else:
                    continue

            if excepts:
                raise Exception("Socket exception")

            if self.request in outs:
                # Send queued target data to the client
                dat = ''.join(cqueue)
                cqueue = []
                sent = self.request.send(dat)
                if sent != len(dat):
                    # requeue the remaining data
                    cqueue.insert(0, dat[sent:])

            if self.request in ins:
                # Receive client data, decode it, and queue for target
                buf = self.request.recv(self.buffer_size)

                if len(buf) == 0:
                    if self.verbose:
                        self.log_message("%s:%s: Client closed connection",
                                         self.server.target_host,
                                         self.server.target_port)
                    raise self.CClose(1000, "Client closed")

                else:
                    #Don't forward pong packets
                    frame = self.decode_hybi(
                        buf, base64=self.base64, logger=self.logger,
                        strict=self.strict_mode)
                    #ignore pongs with no payload
                    if not (frame['opcode'] == 0xA and not frame['payload']):
                        tqueue.append(buf)


            if target in outs:
                # Send queued client data to the target
                dat = ''.join(tqueue)
                tqueue = []
                sent = target.send(dat)
                if sent != len(dat):
                    tqueue.insert(0, dat[sent:])

            if target in ins:
                # Receive target data, encode it and queue for client
                buf = target.recv(self.buffer_size)
                if len(buf) == 0:
                    if self.verbose:
                        self.log_message("%s:%s: Target closed connection",
                                self.server.target_host, self.server.target_port)
                    raise self.CClose(1000, "Target closed")
                cqueue.append(buf)
