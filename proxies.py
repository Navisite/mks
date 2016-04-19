import websockify
import urlparse
import time
import select
import sys
import errno
import six

class SimpleProxyHandler(websockify.ProxyRequestHandler):
    """
    Simple proxy that expects both sides to support websockets
    """

    def _recv_line(self, sock):
        line = []
        while True:
            character = sock.recv(1)
            line.append(character)
            if character == six.b("\n"):
                break
        return six.b("").join(line)

    def _read_headers(self, sock):
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
        print upgrade
        tsock.send(upgrade)
        status, headers = self._read_headers(tsock)
        if status != 101:
            raise Exception("Bad Response, %s, %s" % (status, headers))
        self.do_proxy(tsock)

    def do_proxy(self, target):
        cqueue = []
        tqueue = []
        rlist = [self.request, target]

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
                    self.send_ping()

            if tqueue: wlist.append(target)
            if cqueue: wlist.append(self.request)
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

            if excepts: raise Exception("Socket exception")

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
                    raise self.CClose(1000, "Target closed")

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
