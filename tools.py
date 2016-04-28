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
Tools for MKS
"""

import getpass
import requests
import urllib
import urlparse

requests.packages.urllib3.disable_warnings()

def vsphere_url(vm, host, args):
    # Generates console URL for vSphere versions prior 6.0
    ticket = vm.AcquireTicket('mks')
    vm_host = ticket.host if ticket.host else host
    path = '?host={0}&port={1}&ticket={2}&cfgFile={3}&thumbprint={4}'.format(
        vm_host, ticket.port, ticket.ticket, ticket.cfgFile,
        ticket.sslThumbprint)
    base_url = "http://rgerganov.github.io/noVNC/5"
    url = "{0}/vnc_auto.html?host={1}&port={2}&path={3}".format(
        base_url, args.mhost, args.mport, urllib.quote(path))
    return url

def vsphere6_url(vm, host):
    # Generates console URL for vSphere 6
    ticket = vm.AcquireTicket('webmks')
    vm_host = ticket.host if ticket.host else host
    path = "ticket/" + ticket.ticket
    base_url = "https://rgerganov.github.io/noVNC/6"
    url = "{0}/vnc_auto.html?host={1}&path={2}".format(base_url, vm_host,
                                                       urllib.quote(path))
    return url
