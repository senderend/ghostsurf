#!/usr/bin/env python3
"""
Local smoke test for ghostsurf's capture listeners.

Starts a fake IWA site (NTLM only, auth bound to the TCP connection like IIS) on
localhost, runs ghostsurf.py against it on unprivileged ports, sends NTLM auth into
each listener the way a real source would, then checks two things for each one:

  1. the relayed session shows up in ghostsurf's REST API
  2. a page fetched through the SOCKS proxy with that session's cookie comes back
     from the target as the right user

Listeners covered:
  http  browser-style NTLM over HTTP
  smb   SMB session setup (coerced machine auth, poisoned users)
  raw   lsarelayx-style length-prefixed NTLM over TCP
  rpc   endpoint mapper lookup, then an NTLM bind to the MS-RPRN interface, which is
        what a PrinterBug callback from Windows 11 22H2+ / Server 2025 looks like

The WCF listener isn't covered.

Needs no root and no network. Run it with ghostsurf's venv so impacket is installed:

    ./ghostsurf -h                      # first run creates ./venv
    venv/bin/python tests/smoke_test.py

Options:
    --listeners http,smb    test a subset (default: every listener this ghostsurf has)
    --ghostsurf PATH        ghostsurf.py to test (default: the one in this repo)
    --debug                 print ghostsurf's output as it runs

Exits 0 when every tested listener relays and serves a page through SOCKS.
"""
import argparse
import base64
import http.client
import http.server
import json
import os
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import urllib.parse

from impacket import ntlm

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOMAIN = 'LAB'
PASSWORD = 'Smoke-Test-1!'
SESSION_COOKIE = 'ntlmrelay_session'
MS_RPRN = ('12345678-1234-ABCD-EF00-0123456789AB', '1.0')
ALL_LISTENERS = ('http', 'smb', 'raw', 'rpc')


# --- Fake IWA target ----------------------------------------------------------------

def build_challenge():
    flags = (ntlm.NTLMSSP_NEGOTIATE_UNICODE | ntlm.NTLMSSP_REQUEST_TARGET |
             ntlm.NTLMSSP_NEGOTIATE_NTLM | ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
             ntlm.NTLMSSP_TARGET_TYPE_DOMAIN | ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
             ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | ntlm.NTLMSSP_NEGOTIATE_VERSION |
             ntlm.NTLMSSP_NEGOTIATE_128 | ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH)
    domain = DOMAIN.encode('utf-16le')
    av = ntlm.AV_PAIRS()
    av[ntlm.NTLMSSP_AV_HOSTNAME] = 'WEB01'.encode('utf-16le')
    av[ntlm.NTLMSSP_AV_DOMAINNAME] = DOMAIN.encode('utf-16le')
    av[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = 'web01.lab.local'.encode('utf-16le')
    av[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = 'lab.local'.encode('utf-16le')
    avdata = av.getData()
    challenge = ntlm.NTLMAuthChallenge()
    challenge['flags'] = flags
    challenge['domain_len'] = len(domain)
    challenge['domain_max_len'] = len(domain)
    challenge['domain_offset'] = 40 + 16
    challenge['challenge'] = os.urandom(8)
    challenge['domain_name'] = domain
    challenge['TargetInfoFields_len'] = len(avdata)
    challenge['TargetInfoFields_max_len'] = len(avdata)
    challenge['TargetInfoFields'] = avdata
    challenge['TargetInfoFields_offset'] = 40 + 16 + len(domain)
    challenge['Version'] = b'\x0a\x00\x63\x45\x00\x00\x00\x0f'
    challenge['VersionLen'] = 8
    return challenge.getData()


class FakeIWAHandler(http.server.BaseHTTPRequestHandler):
    """401 NTLM until a connection completes the handshake, then 200 for every request on
    that connection, including ones without an Authorization header (like HTTP.sys).
    Any AUTHENTICATE is accepted; credentials aren't checked."""
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.authed_as = None

    def log_message(self, fmt, *args):
        pass

    def reply(self, code, headers=None, body=b''):
        self.send_response(code)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def handle_any(self):
        auth = self.headers.get('Authorization', '')
        if not auth.startswith(('NTLM ', 'Negotiate ')):
            if self.authed_as:
                self.reply(200, {'Content-Type': 'text/plain'},
                           ('relayed as %s' % self.authed_as).encode())
            else:
                self.reply(401, {'WWW-Authenticate': 'NTLM'})
            return
        scheme, blob = auth.split(' ', 1)
        token = base64.b64decode(blob)
        message_type = token[8] if token.startswith(b'NTLMSSP\x00') else None
        if message_type == 1:
            self.reply(401, {'WWW-Authenticate': '%s %s' % (scheme, base64.b64encode(build_challenge()).decode())})
        elif message_type == 3:
            msg = ntlm.NTLMAuthChallengeResponse()
            msg.fromString(token)
            self.authed_as = '%s\\%s' % (msg['domain_name'].decode('utf-16le', 'replace'),
                                         msg['user_name'].decode('utf-16le', 'replace'))
            self.reply(200, {'Content-Type': 'text/plain'}, ('relayed as %s' % self.authed_as).encode())
        else:
            self.reply(400)

    do_GET = do_HEAD = do_POST = handle_any


class FakeIWAServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# --- Helpers -----------------------------------------------------------------------

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError('connection closed after %d of %d bytes' % (len(data), n))
        data += chunk
    return data


def connect_retry(port, timeout=10):
    deadline = time.time() + 5
    while True:
        try:
            return socket.create_connection(('127.0.0.1', port), timeout=timeout)
        except ConnectionRefusedError:
            if time.time() > deadline:
                raise
            time.sleep(0.2)


def type3_for(negotiate, challenge_blob, user, service):
    authenticate, _ = ntlm.getNTLMSSPType3(negotiate, challenge_blob, user, PASSWORD, DOMAIN, service=service)
    return authenticate.getData()


# --- Auth sources ------------------------------------------------------------------

def send_http(port, user):
    connect_retry(port).close()
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    negotiate = ntlm.getNTLMSSPType1('WS01', DOMAIN)
    conn.request('GET', '/', headers={'Authorization': 'NTLM ' + base64.b64encode(negotiate.getData()).decode()})
    resp = conn.getresponse()
    resp.read()
    header = resp.getheader('WWW-Authenticate') or ''
    if resp.status != 401 or not header.startswith('NTLM '):
        return 'NEGOTIATE got HTTP %d with no challenge' % resp.status
    authenticate = type3_for(negotiate, base64.b64decode(header.split(' ', 1)[1]), user, 'http')
    conn.request('GET', '/', headers={'Authorization': 'NTLM ' + base64.b64encode(authenticate).decode()})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return 'AUTHENTICATE got HTTP %d' % resp.status


def send_smb(port, user):
    from impacket.smbconnection import SMBConnection
    connect_retry(port).close()
    try:
        smb = SMBConnection('127.0.0.1', '127.0.0.1', sess_port=port, timeout=15)
        smb.login(user, PASSWORD, DOMAIN)
        return 'session setup accepted'
    except Exception as e:
        return 'session setup ended with: %s' % str(e)[:80]


def send_raw(port, user):
    sock = connect_retry(port)
    try:
        negotiate = ntlm.getNTLMSSPType1('WS01', DOMAIN)
        data = negotiate.getData()
        sock.sendall(struct.pack('h', len(data)) + data)
        challenge_len = struct.unpack('h', recv_exact(sock, 2))[0]
        challenge_blob = recv_exact(sock, challenge_len)
        authenticate = type3_for(negotiate, challenge_blob, user, 'host')
        sock.sendall(struct.pack('h', len(authenticate)) + authenticate)
        recv_exact(sock, 2)
        ok = struct.unpack('?', recv_exact(sock, 1))[0]
        return 'relay reported %s' % ('success' if ok else 'failure')
    except Exception as e:
        return 'failed: %s' % str(e)[:80]
    finally:
        sock.close()


def send_rpc(port, user):
    from impacket.dcerpc.v5 import epm, transport
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
    from impacket.uuid import uuidtup_to_bin
    connect_retry(port).close()
    binding = 'ncacn_ip_tcp:127.0.0.1[%d]' % port

    # Like the PrinterBug callback: an unauthenticated endpoint mapper lookup first...
    note = ''
    try:
        dce = transport.DCERPCTransportFactory(binding).get_dce_rpc()
        dce.connect()
        epm.hept_map('127.0.0.1', uuidtup_to_bin(MS_RPRN), protocol='ncacn_ip_tcp', dce=dce)
        dce.disconnect()
        note = 'endpoint mapper answered; '
    except Exception as e:
        note = 'endpoint mapper lookup failed (%s); ' % str(e)[:60]

    # ...then an authenticated bind to the printer interface.
    try:
        rpc = transport.DCERPCTransportFactory(binding)
        rpc.set_credentials(user, PASSWORD, DOMAIN, '', '')
        rpc.set_connect_timeout(15)
        dce = rpc.get_dce_rpc()
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.connect()
        dce.bind(uuidtup_to_bin(MS_RPRN))
        time.sleep(1)  # the relay finishes after AUTH3, which gets no reply
        dce.disconnect()
        return note + 'bind sent'
    except Exception as e:
        return note + 'bind ended with: %s' % str(e)[:80]


SOURCES = {'http': send_http, 'smb': send_smb, 'raw': send_raw, 'rpc': send_rpc}


# --- Checking ghostsurf ------------------------------------------------------------

def api_relays(api_port):
    conn = http.client.HTTPConnection('127.0.0.1', api_port, timeout=5)
    conn.request('GET', '/ntlmrelayx/api/v1.0/relays')
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    if resp.status != 200:
        raise RuntimeError('API returned HTTP %d' % resp.status)
    return json.loads(body)


def fetch_through_socks(socks_port, target_port, username):
    """GET / through ghostsurf's SOCKS5 proxy, picking the session with ghostsurf's cookie."""
    sock = socket.create_connection(('127.0.0.1', socks_port), timeout=15)
    try:
        sock.sendall(b'\x05\x01\x00')
        if recv_exact(sock, 2) != b'\x05\x00':
            return None, 'SOCKS greeting refused'
        sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('>H', target_port))
        reply = recv_exact(sock, 10)
        if reply[1] != 0:
            return None, 'SOCKS CONNECT refused (code %d)' % reply[1]
        request = ('GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nCookie: %s=%s\r\nConnection: close\r\n\r\n'
                   % (target_port, SESSION_COOKIE, urllib.parse.quote(username)))
        sock.sendall(request.encode())
        response = b''
        while b'\r\n\r\n' not in response:
            chunk = sock.recv(8192)
            if not chunk:
                break
            response += chunk
        head, _, body = response.partition(b'\r\n\r\n')
        status = int(head.split(b' ', 2)[1]) if head.startswith(b'HTTP/') else None
        length = 0
        for line in head.split(b'\r\n')[1:]:
            name, _, value = line.partition(b':')
            if name.strip().lower() == b'content-length':
                length = int(value.strip())
        while len(body) < length:
            chunk = sock.recv(8192)
            if not chunk:
                break
            body += chunk
        return status, body.decode('utf-8', 'replace')
    finally:
        sock.close()


def ghostsurf_flags(ghostsurf_py, python):
    out = subprocess.run([python, ghostsurf_py, '-h'], cwd=os.path.dirname(ghostsurf_py),
                         capture_output=True, text=True, timeout=60)
    return out.stdout + out.stderr


def main():
    parser = argparse.ArgumentParser(description='Smoke-test ghostsurf capture listeners against a local fake IWA site')
    parser.add_argument('--listeners', default=None, help='comma-separated subset of: %s' % ','.join(ALL_LISTENERS))
    parser.add_argument('--ghostsurf', default=os.path.join(REPO_ROOT, 'ghostsurf.py'), help='ghostsurf.py to test')
    parser.add_argument('--python', default=sys.executable, help='interpreter for ghostsurf (default: this one)')
    parser.add_argument('--debug', action='store_true', help="print ghostsurf's output as it runs")
    args = parser.parse_args()

    ghostsurf_py = os.path.abspath(args.ghostsurf)
    help_text = ghostsurf_flags(ghostsurf_py, args.python)
    has_rpc = '--rpc-port' in help_text

    if args.listeners:
        wanted = [name.strip().lower() for name in args.listeners.split(',') if name.strip()]
        unknown = [name for name in wanted if name not in ALL_LISTENERS]
        if unknown:
            parser.error('unknown listener(s): %s' % ', '.join(unknown))
    else:
        wanted = [name for name in ALL_LISTENERS if name != 'rpc' or has_rpc]

    results = {name: {'source': '', 'relayed': False, 'socks': ''} for name in wanted}
    if 'rpc' in wanted and not has_rpc:
        results['rpc']['source'] = 'this ghostsurf.py has no --rpc-port option'

    ports = {name: free_port() for name in ('target', 'http', 'smb', 'raw', 'rpc', 'socks', 'api')}

    target = FakeIWAServer(('127.0.0.1', ports['target']), FakeIWAHandler)
    threading.Thread(target=target.serve_forever, daemon=True).start()

    cmd = [args.python, ghostsurf_py, '-t', 'http://127.0.0.1:%d/' % ports['target'], '-r', '-i', '127.0.0.1',
           '--socks-port', str(ports['socks']), '--api-port', str(ports['api']), '--no-wcf-server']
    for name, flag in (('http', '--http-port'), ('smb', '--smb-port'), ('raw', '--raw-port')):
        if name in wanted:
            cmd += [flag, str(ports[name])]
        else:
            cmd += ['--no-%s-server' % name]
    if has_rpc:
        cmd += ['--rpc-port', str(ports['rpc'])] if 'rpc' in wanted else ['--no-rpc-server']

    output = []
    proc = subprocess.Popen(cmd, cwd=os.path.dirname(ghostsurf_py), stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    def pump():
        for line in proc.stdout:
            output.append(line.rstrip('\n'))
            if args.debug:
                print('  | ' + line.rstrip('\n'))
    threading.Thread(target=pump, daemon=True).start()

    failed = False
    try:
        deadline = time.time() + 30
        while True:
            if proc.poll() is not None:
                raise RuntimeError('ghostsurf exited early with code %d' % proc.returncode)
            try:
                api_relays(ports['api'])
                if any('Servers started' in line for line in output):
                    break
            except (OSError, RuntimeError, ValueError):
                pass
            if time.time() > deadline:
                raise RuntimeError('ghostsurf did not come up within 30s')
            time.sleep(0.3)
        time.sleep(1)

        for name in wanted:
            if results[name]['source']:
                continue
            user = 'smoke_%s' % name
            try:
                results[name]['source'] = SOURCES[name](ports[name], user)
            except Exception as e:
                results[name]['source'] = 'failed: %s' % str(e)[:80]
            time.sleep(0.5)

        expected = {('%s/SMOKE_%s' % (DOMAIN, name.upper())): name for name in wanted}
        registered = set()
        deadline = time.time() + 10
        while time.time() < deadline:
            registered = {row[2].upper() for row in api_relays(ports['api'])}
            if set(expected) <= registered:
                break
            time.sleep(0.5)

        for username, name in expected.items():
            if username not in registered:
                continue
            results[name]['relayed'] = True
            status, body = fetch_through_socks(ports['socks'], ports['target'], username)
            if status == 200 and ('smoke_%s' % name) in body.lower():
                results[name]['socks'] = 'HTTP 200, %s' % body.strip()
            else:
                results[name]['socks'] = 'unexpected: %s %s' % (status, body.strip()[:60])
    except Exception as e:
        failed = True
        print('error: %s' % e)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        target.shutdown()

    print('\nghostsurf: %s' % ghostsurf_py)
    print('%-5s %-8s %-48s %s' % ('', 'relayed', 'source', 'page through SOCKS'))
    for name in wanted:
        r = results[name]
        ok = r['relayed'] and r['socks'].startswith('HTTP 200')
        failed = failed or not ok
        print('%-5s %-8s %-48s %s' % (name, 'yes' if r['relayed'] else 'NO', r['source'][:48], r['socks'] or '-'))

    if failed:
        errors = [line for line in output if '[-]' in line or 'Traceback' in line or 'Error' in line]
        if errors and not args.debug:
            print('\nghostsurf errors:')
            for line in errors[-15:]:
                print('  | ' + line)
        print('\nFAIL')
        return 1
    print('\nPASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
