#!/usr/bin/env python3
# rpcauthmap.py
#
# RPC endpoint enumerator + NTLM auth / RPC-layer protection prober
# (Impacket / Python 3). Based on CORE Security Technologies' rpcdump.py.
#
# For each registered interface on each target it:
#   1. Reads the endpoint list from the endpoint mapper (TCP/135). The mapper
#      returns the exact dynamic port per interface, so no port scan is needed.
#   2. Attempts binds at escalating authentication levels to find the lowest
#      one the server accepts (the enforced floor):
#         none      -> unauthenticated bind allowed
#         connect   -> authenticated but UNSIGNED bind allowed (relay-viable)
#         integrity -> packet integrity required (signing enforced)
#         privacy   -> packet integrity + encryption required
#
# Interpretation for relay: a relayed NTLM session has no session key and so
# cannot sign. If the floor is "connect", signing is not required and the
# endpoint is a candidate relay destination. If the floor is "integrity" or
# "privacy", a relay fails at the RPC layer regardless of SMB settings.
#
# Targets can be a single host, a CIDR (192.168.1.0/24), a comma-separated
# list, or a file of hosts referenced as @hosts.txt. Hosts are swept
# concurrently.
#
# Caveat: this tests acceptance at BIND time. A server can, in principle, accept
# a low-level bind and enforce a higher level only at call time on specific
# opnums. Confirm anything ambiguous with a real authenticated call or a capture.
#
# For authorized security testing only.

import os
import sys
import logging
import argparse
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from impacket import version, uuid
from impacket.examples import logger
from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5.rpcrt import (
    RPC_C_AUTHN_WINNT,
    RPC_C_AUTHN_LEVEL_NONE,
    RPC_C_AUTHN_LEVEL_CONNECT,
    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    DCERPCException,
)

# Ordered lowest to highest. 'none' is unauthenticated; the rest use NTLMSSP.
AUTH_LEVELS = [
    ('none',      RPC_C_AUTHN_LEVEL_NONE,          False),
    ('connect',   RPC_C_AUTHN_LEVEL_CONNECT,       True),
    ('integrity', RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, True),
    ('privacy',   RPC_C_AUTHN_LEVEL_PKT_PRIVACY,   True),
]

_print_lock = threading.Lock()


class RPCAuthMap:
    def __init__(self, username='', password='', domain='', hashes=None,
                 show_all=False, probe_pipes=True, timeout=5):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        if hashes:
            self.__lmhash, self.__nthash = hashes.split(':')
        self.__show_all = show_all
        self.__probe_pipes = probe_pipes
        self.__timeout = timeout

    def scan(self, target):
        """Scan one host. Returns (relay_count, list_of_output_lines)."""
        out = []
        entries = self.__fetch_endpoints(target)
        if entries is None:
            return 0, ['[!] %s : endpoint mapper unreachable' % target]
        if not entries:
            return 0, ['[-] %s : no endpoints returned' % target]

        seen = set()
        results = []
        for entry in entries:
            floors = entry['tower']['Floors']
            iface = str(floors[0])                       # "uuid vX.Y"
            binding = self.__rehost(epm.PrintStringBinding(floors), target)
            annotation = self.__clean_annotation(entry['annotation'])
            key = (iface, binding)
            if key in seen:
                continue
            seen.add(key)
            results.append((iface, binding, annotation))

        out.append('=== %s : %d unique endpoint(s) ===' % (target, len(results)))
        relay_candidates = 0
        for iface, binding, annotation in results:
            info = self.__probe(iface, binding)
            if info['verdict'] == 'relay-viable':
                relay_candidates += 1
            if info['ntlm'] or self.__show_all:
                out.extend(self.__format_entry(iface, binding, annotation, info))
        out.append('--- %s : %d relay-viable RPC endpoint(s) ---'
                   % (target, relay_candidates))
        return relay_candidates, out

    def __fetch_endpoints(self, target):
        rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s' % target)
        rpctransport.set_dport(135)
        try:
            rpctransport.set_connect_timeout(self.__timeout)
        except Exception:
            pass
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password,
                                         self.__domain, self.__lmhash,
                                         self.__nthash)
        try:
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            resp = epm.hept_lookup(target, dce=dce)
            dce.disconnect()
            return resp
        except Exception:
            return None

    def __probe(self, iface, binding):
        proto = binding.split(':')[0]
        base = {'ntlm': False, 'floor': None, 'accepted': {},
                'verdict': 'n/a', 'note': ''}

        if proto == 'ncacn_np' and not self.__probe_pipes:
            base['verdict'] = 'skipped'
            base['note'] = 'named pipe (probing disabled)'
            return base
        if proto not in ('ncacn_ip_tcp', 'ncacn_np'):
            base['verdict'] = 'skipped'
            base['note'] = 'transport not probed (%s)' % proto
            return base

        try:
            iface_bin = uuid.uuidtup_to_bin(
                (iface.split(' ')[0], iface.split('v')[-1]))
        except Exception as e:
            base['verdict'] = 'error'
            base['note'] = 'could not parse interface id: %s' % e
            return base

        for name, level, authenticated in AUTH_LEVELS:
            ok, _detail = self.__try_bind(binding, iface_bin, level, authenticated)
            base['accepted'][name] = ok

        auth_ok = {n: base['accepted'][n] for n in ('connect', 'integrity', 'privacy')}
        base['ntlm'] = any(auth_ok.values())

        for name in ('connect', 'integrity', 'privacy'):
            if base['accepted'][name]:
                base['floor'] = name
                break

        if base['floor'] == 'connect':
            base['verdict'] = 'relay-viable'
        elif base['floor'] in ('integrity', 'privacy'):
            base['verdict'] = 'hardened'
        elif base['accepted'].get('none'):
            base['verdict'] = 'anon-only'
        else:
            base['verdict'] = 'no-bind'

        return base

    def __try_bind(self, binding, iface_bin, level, authenticated):
        rpctransport = transport.DCERPCTransportFactory(binding)
        if authenticated and hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(self.__username, self.__password,
                                         self.__domain, self.__lmhash,
                                         self.__nthash)
        try:
            rpctransport.set_connect_timeout(self.__timeout)
        except Exception:
            pass

        dce = rpctransport.get_dce_rpc()
        try:
            if authenticated:
                dce.set_auth_type(RPC_C_AUTHN_WINNT)
            dce.set_auth_level(level)
        except Exception:
            pass

        try:
            dce.connect()
            dce.bind(iface_bin)
            return True, ''
        except DCERPCException as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)
        finally:
            self.__safe_disconnect(dce)

    @staticmethod
    def __safe_disconnect(dce):
        try:
            dce.disconnect()
        except Exception:
            pass

    @staticmethod
    def __rehost(binding, target):
        # PrintStringBinding embeds whatever host the tower carried (sometimes a
        # NetBIOS name). Force the host we actually scanned so probing connects
        # by IP. Format is proto:host[endpoint].
        import re
        m = re.match(r'^(ncacn_ip_tcp|ncacn_np|ncacn_http):(.*?)(\[.*\])$', binding)
        if m:
            return '%s:%s%s' % (m.group(1), target, m.group(3))
        return binding

    @staticmethod
    def __clean_annotation(annotation):
        if isinstance(annotation, bytes):
            annotation = annotation.decode('utf-8', errors='replace')
        return (annotation or '').rstrip('\x00').strip()

    @staticmethod
    def __format_entry(iface, binding, annotation, info):
        tag = {
            'relay-viable': '[+]',
            'hardened':     '[-]',
            'anon-only':    '[a]',
            'no-bind':      '[x]',
            'skipped':      '[ ]',
            'error':        '[!]',
        }.get(info['verdict'], '[?]')

        acc = info['accepted']
        levels_str = ', '.join(
            '%s=%s' % (n, 'ok' if acc.get(n) else '-')
            for n in ('none', 'connect', 'integrity', 'privacy')
        )

        lines = ['%s %s' % (tag, binding),
                 '    Interface : %s' % iface]
        if annotation:
            lines.append('    Service   : %s' % annotation)
        lines.append('    NTLM      : %s' % ('yes' if info['ntlm'] else 'no'))
        lines.append('    Levels    : %s' % levels_str)
        lines.append('    Floor     : %s' % (info['floor'] or 'none/anon'))
        lines.append('    Verdict   : %s%s' % (
            info['verdict'], ' (%s)' % info['note'] if info['note'] else ''))
        lines.append('')
        return lines


def expand_targets(spec):
    """Expand a target spec into a list of host strings.

    Supports: single host/IP, CIDR (192.168.1.0/24), comma-separated list,
    and @file (one host per line, # comments allowed).
    """
    hosts = []
    for token in spec.split(','):
        token = token.strip()
        if not token:
            continue
        if token.startswith('@'):
            path = token[1:]
            if not os.path.isfile(path):
                print('[-] Host file not found: %s' % path)
                continue
            with open(path) as fh:
                for line in fh:
                    line = line.split('#', 1)[0].strip()
                    if line:
                        hosts.extend(expand_targets(line))
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
            if net.num_addresses > 1:
                hosts.extend(str(h) for h in net.hosts())
            else:
                hosts.append(str(net.network_address))
        except ValueError:
            hosts.append(token)          # hostname or single IP
    # De-duplicate, preserve order.
    seen, ordered = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            ordered.append(h)
    return ordered


def parse_creds(prefix):
    """Split the optional [[domain/]user[:pass]@] credential prefix."""
    import re
    domain, username, password = re.compile(
        r'(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?'
    ).match(prefix).groups('')
    return domain or '', username or '', password or ''


def main():
    print(version.BANNER)
    parser = argparse.ArgumentParser(
        add_help=True,
        description='Enumerate RPC endpoints across a host or subnet; report '
                    'NTLM acceptance and the enforced RPC auth level per '
                    'interface.'
    )
    parser.add_argument('target', action='store',
                        help='[[domain/]user[:pass]@]<host|CIDR|list|@file>')
    parser.add_argument('-all', '--all', action='store_true', dest='show_all',
                        help='show every endpoint, not just NTLM-capable ones')
    parser.add_argument('-no-pipes', action='store_true', dest='no_pipes',
                        help='do not probe named-pipe (ncacn_np) bindings')
    parser.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH',
                        help='NTLM hashes, format LMHASH:NTHASH')
    parser.add_argument('-timeout', action='store', type=int, default=5,
                        help='per-attempt connect timeout in seconds (default 5)')
    parser.add_argument('-threads', action='store', type=int, default=10,
                        help='concurrent hosts to scan (default 10)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init()
    logging.getLogger().setLevel(logging.CRITICAL)

    # Separate an optional credential prefix from the target spec.
    if '@' in options.target:
        prefix, spec = options.target.rsplit('@', 1)
        domain, username, password = parse_creds(prefix)
    else:
        domain = username = password = ''
        spec = options.target

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass('Password:')

    targets = expand_targets(spec)
    if not targets:
        print('[-] No valid targets parsed.')
        sys.exit(1)

    print('[*] Sweeping %d host(s) with %d thread(s)...\n'
          % (len(targets), options.threads))

    def worker(host):
        mapper = RPCAuthMap(
            username=username, password=password, domain=domain,
            hashes=options.hashes, show_all=options.show_all,
            probe_pipes=not options.no_pipes, timeout=options.timeout,
        )
        return host, mapper.scan(host)

    total_relay = 0
    hosts_with_hits = 0
    with ThreadPoolExecutor(max_workers=max(1, options.threads)) as pool:
        futures = [pool.submit(worker, h) for h in targets]
        for fut in as_completed(futures):
            host, (relay_count, lines) = fut.result()
            if relay_count:
                hosts_with_hits += 1
            total_relay += relay_count
            with _print_lock:
                print('\n'.join(lines))
                print('')

    print('[*] Sweep complete: %d relay-viable RPC endpoint(s) across %d host(s).'
          % (total_relay, hosts_with_hits))


if __name__ == '__main__':
    main()
