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

import base64
import hashlib
import logging
import os
import random
import socket
import ssl
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

class AuthdRequestHandler(websockify.ProxyRequestHandler):

    def _handle_esx_init(self, tsock):
        """
        We need to handle some negotiation with
        noVNC since ESX doesn't
        """
        version = "RFB 003.008"
        self.log_message("Sending version %s", version)
        self.send_frames([version+"\n",])
        agreed_version, closed = self.recv_frames()
        agreed_version = agreed_version[0].split()[0]
        self.log_message("Received version %s", agreed_version)
        self.log_message("Sending security types")
        self.send_frames(["\x01\x01"])
        agreed_security_type, closed =  self.recv_frames()
        self.log_message("Agreed security type is %s",
                      agreed_security_type[0].split()[0])
        self.log_message("Sending OK security result")
        self.send_frames(["\x00\x00\00\x00"])
        shared_flag, closed = self.recv_frames()
        self.log_message("Received shared flag %s", shared_flag[0].split()[0])
        self.log_message("Sending VM info")
        self.send_frames(tsock.recv(1024))
        self.log_message("init handling finished")

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
        self._handle_esx_init(tsock)
        self.do_proxy(tsock)
