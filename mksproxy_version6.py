#!/usr/bin/env python
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

import argparse
import authd
import logging
import sys
import websockify
import proxies

def stdout_logging():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    root.addHandler(ch)

def run_websockets_proxy(args):
    logging.debug('Starting MKS proxy on {0}:{1}'.format(args.host, args.port))
    proxy = websockify.WebSocketProxy(
        listen_host=args.host,
        listen_port=args.port,
        verbose=True,
        web=args.web,
        file_only=True,
        daemon=args.daemon,
        heartbeat=args.heartbeat,
        RequestHandlerClass=proxies.SimpleProxyHandler,
        cert=args.cert)
    proxy.record = args.record
    proxy.start_server()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--host", default='localhost',
                        help="MKS proxy host (default 'localhost')")
    parser.add_argument("-p", "--port",  type=int, default=6090,
                        help="Heartbeat seconds, 0 for off) (default 20)")
    parser.add_argument("-b", "--heartbeat", type=int, default=20,
                        help="MKS proxy port (default 6090)")
    parser.add_argument("--web", help="web location")
    parser.add_argument("-d", "--daemon", action="store_true",
                        help="Run proxy server as a daemon")
    parser.add_argument("-r", "--record", type=str, default=None,
                        help="Data record file")
    parser.add_argument("-c", "--cert", type=str, default="",
                        help="SSL certificate")
    args = parser.parse_args()
    stdout_logging()
    run_websockets_proxy(args)
