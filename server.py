#!/usr/bin/env python3
import argparse
import base64
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import logging
import sys
import textwrap
import re
import urllib.parse

from autowg import Tunnel, DirectBCDConverter, MetansConverter

TUNNEL = None
CFG =  {}
AUTH = None
CN_PATTERN = None

class RequestHandler(BaseHTTPRequestHandler):
    def _respond_json(self, js, write=True):
        data = json.dumps(js, sort_keys=True, indent=4)
        data += "\n"

        data = data.encode('utf-8')

        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=UTF-8')
        self.send_header('Content-Length', len(data))
        self.end_headers()

        if write:
            self.wfile.write(data)

    def _respond_plain(self, txt, write=True, code=200):
        data = txt + "\n"
        data = data.encode('utf-8')

        self.send_response(code)
        self.send_header('Content-Type', 'text/plain; charset=UTF-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()

        if write:
            self.wfile.write(data)

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)

        if 'Content-Length' not in self.headers:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return

        payload_len = int(self.headers['Content-Length'])
        payload = self.rfile.read(payload_len) # FIXME: should have a timeout

        if not 'X-Client-Subject' in self.headers:
            self.send_error(HTTPStatus.FORBIDDEN, 'permission denied')
            return

        cn_match = CN_PATTERN.match(self.headers['X-Client-Subject'])
        if not cn_match:
            self.send_error(HTTPStatus.FORBIDDEN, 'permission denied')
            return

        cn = cn_match.group(1)

        if url.path != CFG['http_prefix'] + 'v1/register':
            self.send_error(HTTPStatus.NOT_FOUND, 'not found')
            return

        pubkey = ''
        ip = None
        try:
            pubkey = payload.decode('ascii')
            ip = TUNNEL.set_peer(cn, pubkey)

            logging.info('registered peer "%s" (IP: %s) with pubkey "%s"' % (cn, ip, pubkey))
        except:
            logging.error('failed to process client request from "%s" with payload "%s"' % (cn, payload), exc_info=sys.exc_info())
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

        response = textwrap.dedent(f"""\
            endpoint={CFG['wg_endpoint']}
            pubkey={CFG['wg_pubkey']}
            route={CFG['route']}
            ip={ip}
            keepalive=25
            """)

        self._respond_plain(response.strip())

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)

        if AUTH is None or self.headers.get('Authorization') != 'Basic ' + AUTH:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header('WWW-Authenticate', 'Basic realm=auth')
            self.end_headers()

            return

        if url.path == CFG['http_prefix'] + 'v1/peers.json':
            self._respond_json(TUNNEL.peerstats_all())
            return


def main():
    parser = argparse.ArgumentParser(description='Wireguard autoconfig', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--pool', help='IPv6 prefix to assign to clients', required=True)
    parser.add_argument('--route', help='IPv6 route to push to clients', required=True)
    parser.add_argument('--endpoint', help='Wireguard endpoint (host/ip, port ist inferred)', required=True)
    parser.add_argument('--http-host', help='HTTP host to listen on', default='')
    parser.add_argument('--http-port', type=int, help='HTTP port to listen on', default=3000)
    parser.add_argument('--http-prefix', help='HTTP URL prefix', default='/')
    parser.add_argument('--cn-pattern', help='Regex to extract the peer name from the CN', default='([0-9a-zA-Z]+)')
    parser.add_argument('--converter', help='Name-to-IP converter', default='direct-bcd', choices=['direct-bcd', 'metans'])
    parser.add_argument('--metans-template', help='Prefix template for metans name generation')
    parser.add_argument('interface', help='Wireguard interface to manage')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    global TUNNEL, CFG, AUTH, CN_PATTERN

    if 'HTTP_AUTH' in os.environ:
        AUTH = base64.b64encode(os.environ['HTTP_AUTH'].encode('ascii')).decode('ascii')

    CN_PATTERN = re.compile(r'CN=' + args.cn_pattern)

    if args.converter == 'direct-bcd':
        converter = DirectBCDConverter()
    elif args.converter == 'metans':
        converter = MetansConverter(args.metans_template)
    else:
        logging.error('unknown converter "%s"' % args.converter)
        return 1

    TUNNEL = Tunnel(args.interface, args.pool, converter)
    TUNNEL.flush()
    tun_cfg = TUNNEL.get_config()

    CFG = {
        'route': args.route,
        'http_prefix': args.http_prefix,
        'wg_endpoint': args.endpoint + ':' + str(tun_cfg['port']),
        'wg_pubkey': tun_cfg['pubkey']
    }

    server = HTTPServer((args.http_host, args.http_port), RequestHandler)
    server.serve_forever()

if __name__ == "__main__":
    sys.exit(main())
