# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Config utilities - stripped down for ghostsurf (HTTP-only relay)
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#   senderend - kernelAuth config option for kernel-mode auth workaround
#

class NTLMRelayxConfig:
    def __init__(self):
        self.daemon = True

        # Network
        self.interfaceIp = None
        self.listeningPort = None
        self.ipv6 = False

        # Target
        self.target = None
        self.mode = None
        self.encoding = None
        self.disableMulti = False
        self.keepRelaying = False

        # Protocol
        self.protocolClients = {}
        self.smb2support = False

        # SOCKS
        self.runSocks = False
        self.socksServer = None

        # Kernel-mode auth workaround - probe paths anonymously before using auth
        self.kernelAuth = False
        self.isADCSAttack = False

        # SMB server options (required by impacket's SMBRelayServer but unused for HTTP-only relay)
        self.outputFile = None
        self.dumpHashes = False
        self.SMBServerChallenge = None
        self.remove_mic = False
        self.remove_target = False

    def setSMB2Support(self, value):
        self.smb2support = value

    def setProtocolClients(self, clients):
        self.protocolClients = clients

    def setInterfaceIp(self, ip):
        self.interfaceIp = ip

    def setListeningPort(self, port):
        self.listeningPort = port

    def setRunSocks(self, socks, server):
        self.runSocks = socks
        self.socksServer = server

    def setTargets(self, target):
        self.target = target

    def setDisableMulti(self, disableMulti):
        self.disableMulti = disableMulti

    def setKeepRelaying(self, keepRelaying):
        self.keepRelaying = keepRelaying

    def setEncoding(self, encoding):
        self.encoding = encoding

    def setMode(self, mode):
        self.mode = mode

    def setIPv6(self, use_ipv6):
        self.ipv6 = use_ipv6

    def setKernelAuth(self, kernelAuth):
        self.kernelAuth = kernelAuth


def parse_listening_ports(value):
    ports = set()
    for entry in value.split(","):
        items = entry.split("-")
        if len(items) > 2:
            raise ValueError
        if len(items) == 1:
            ports.add(int(items[0]))
            continue
        item1, item2 = map(int, items)
        if item2 < item1:
            raise ValueError("Upper bound in port range smaller than lower bound")
        ports.update(range(item1, item2 + 1))
    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError("Port %d out of valid range (1-65535)" % port)
    return ports
