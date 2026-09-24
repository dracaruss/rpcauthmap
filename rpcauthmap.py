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
# Relay reasoning: a relayed NTLM session has no session key and cannot sign.
# A floor of "connect" means signing is not required and the endpoint is a
# candidate relay DESTINATION. "integrity"/"privacy" means a relay fails at the
# RPC layer regardless of SMB settings. Knowing an interface accepts a relay is
# only the transport gate; the operation you call is defined by that interface's
# MS-* spec (opnums/NDR), and the relayed identity must be authorized for it.
#
# Targets: single host, CIDR (192.168.1.0/24), comma list, or @file. Swept
# concurrently. Live RPC hosts are grouped under a coloured per-host header;
# dead/no-RPC hosts are summarised, not printed (use -v to show them).
#
# Caveat: this tests acceptance at BIND time. A server can accept a low-level
# bind and enforce a higher level only at call time on specific opnums. Confirm
# anything ambiguous with a real authenticated call or a capture.
#
# For authorized security testing only.

import os
import re
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

# Curated map of relay/coercion-relevant interface UUIDs to their protocol.
# Naming the protocol tells you which MS-* spec (and which impacket / ntlmrelayx
# module) defines the opnums and NDR argument format for that endpoint.
KNOWN_IFACES = {
    '12345678-1234-abcd-ef00-0123456789ab': 'MS-RPRN (spoolss / PrinterBug)',
    'c681d488-d850-11d0-8c52-00c04fd90f7e': 'MS-EFSR (efsrpc / PetitPotam)',
    'df1941c5-fe89-4e79-bf10-463657acf44d': 'MS-EFSR (efsrpc / PetitPotam)',
    '4fc742e0-4a10-11cf-8273-00aa004ae673': 'MS-DFSNM (DFSCoerce)',
    '367abb81-9844-35f1-ad32-98f038001003': 'MS-SCMR (svcctl)',
    '86d35949-83c9-4044-b424-db363231fd0c': 'MS-TSCH (task scheduler)',
    '12345778-1234-abcd-ef00-0123456789ac': 'MS-SAMR (samr)',
    '12345778-1234-abcd-ef00-0123456789ab': 'MS-LSAD/LSARPC (lsarpc)',
    '12345678-1234-abcd-ef00-01234567cffb': 'MS-NRPC (netlogon)',
    'e3514235-4b06-11d1-ab04-00c04fc2dcd2': 'MS-DRSR (drsuapi / DCSync)',
    '99fcfec4-5260-101b-bbcb-00aa0021347a': 'IOXIDResolver (OXID)',
}

_print_lock = threading.Lock()
USE_COLOR = False           # set in main() based on tty / --no-color
_ANSI = re.compile(r'\x1b\[[0-9;]*m')

C = {
    'reset': '\x1b[0m', 'bold': '\x1b[1m',
    'red': '\x1b[31m', 'green': '\x1b[32m', 'yellow': '\x1b[33m',
    'cyan': '\x1b[36m', 'bred': '\x1b[1;31m', 'bgreen': '\x1b[1;32m',
    'bcyan': '\x1b[1;36m',
}


def col(text, name):
    if not USE_COLOR:
        return text
    return '%s%s%s' % (C[name], text, C['reset'])


def strip_ansi(text):
    return _ANSI.sub('', text)


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
        self.__dead = set()

    def scan(self, target):
        """Scan one host. Returns (relay_count, lines, status).

        status: 'unreachable' | 'empty' | 'scanned'.
        """
        self.__dead = set()
        entries = self.__fetch_endpoints(target)
        if entries is None:
            return 0, ['[!] %s : endpoint mapper unreachable' % target], 'unreachable'
        if not entries:
            return 0, ['[-] %s : no endpoints returned' % target], 'empty'

        seen = set()
        results = []
        for entry in entries:
            floors = entry['tower']['Floors']
            iface = str(floors[0])
            binding = self.__rehost(epm.PrintStringBinding(floors), target)
            annotation = self.__clean_annotation(entry['annotation'])
            key = (iface, binding)
            if key in seen:
                continue
            seen.add(key)
            results.append((iface, binding, annotation))

        # Probe everything first, then render grouped under one host header.
        shown = []
        relay_candidates = 0
        for iface, binding, annotation in results:
            info = self.__probe(iface, binding)
            if info['verdict'] == 'relay-viable':
                relay_candidates += 1
            if info['ntlm'] or self.__show_all:
                shown.append((iface, binding, annotation, info))

        header = '=== %s ===  (%d endpoints, %d relay-viable)' % (
            target, len(results), relay_candidates)
        header = col(header, 'bgreen' if relay_candidates else 'bcyan')

        out = [header]
        for iface, binding, annotation, info in shown:
            out.extend(self.__format_entry(iface, binding, annotation, info))
        if not shown:
            out.append('    (no NTLM-capable endpoints; use -all to see the rest)')
        return relay_candidates, out, 'scanned'

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

        if binding in self.__dead:
            base['accepted'] = {n: False for n, _, _ in AUTH_LEVELS}
            base['verdict'] = 'unreachable'
            base['note'] = 'port cached dead'
            return base

        try:
            iface_bin = uuid.uuidtup_to_bin(
                (iface.split(' ')[0], iface.split('v')[-1]))
        except Exception as e:
            base['verdict'] = 'error'
            base['note'] = 'could not parse interface id: %s' % e
            return base

        accepted = {}
        dead = False
        for name, level, authenticated in AUTH_LEVELS:
            status, _detail = self.__try_bind(binding, iface_bin, level, authenticated)
            if status == 'connect-failed':
                dead = True
                accepted[name] = False
                break
            accepted[name] = (status == 'ok')

        if dead:
            self.__dead.add(binding)
            for name, _, _ in AUTH_LEVELS:
                accepted.setdefault(name, False)
            base['accepted'] = accepted
            base['verdict'] = 'unreachable'
            base['note'] = 'connect failed'
            return base

        base['accepted'] = accepted
        base['ntlm'] = any(accepted[n] for n in ('connect', 'integrity', 'privacy'))
        for name in ('connect', 'integrity', 'privacy'):
            if accepted[name]:
                base['floor'] = name
                break

        if base['floor'] == 'connect':
            base['verdict'] = 'relay-viable'
        elif base['floor'] in ('integrity', 'privacy'):
            base['verdict'] = 'hardened'
        elif accepted.get('none'):
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
        except Exception as e:
            return 'connect-failed', str(e)

        try:
            dce.bind(iface_bin)
            return 'ok', ''
        except DCERPCException as e:
            return 'bind-denied', str(e)
        except Exception as e:
            return 'bind-denied', str(e)
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
    def __endpoint_label(binding):
        # ncacn_ip_tcp:host[port] -> "tcp/port"; ncacn_np:host[\pipe\x] -> "np \pipe\x"
        m = re.match(r'^(ncacn_ip_tcp|ncacn_np|ncacn_http):.*?\[(.*)\]$', binding)
        if not m:
            return binding
        proto = {'ncacn_ip_tcp': 'tcp', 'ncacn_np': 'np', 'ncacn_http': 'http'}[m.group(1)]
        return '%s/%s' % (proto, m.group(2))

    def __format_entry(self, iface, binding, annotation, info):
        verdict = info['verdict']
        tag = {
            'relay-viable': '[+]', 'hardened': '[-]', 'anon-only': '[a]',
            'no-bind': '[x]', 'unreachable': '[u]', 'skipped': '[ ]',
            'error': '[!]',
        }.get(verdict, '[?]')

        # Protocol name from the interface UUID (falls back to EPM annotation).
        proto_name = KNOWN_IFACES.get(iface.split(' ')[0].lower(), annotation or '')

        # Colour the levels string; an accepted low level is the dangerous signal.
        acc = info['accepted']
        parts = []
        for n in ('none', 'connect', 'integrity', 'privacy'):
            ok = acc.get(n)
            token = '%s=%s' % (n, 'ok' if ok else '-')
            if ok and n in ('none', 'connect'):
                token = col(token, 'red')          # unsigned/anon = dangerous
            elif ok:
                token = col(token, 'green')        # integrity/privacy = safe
            parts.append(token)
        levels_str = ', '.join(parts)

        if verdict == 'relay-viable':
            vshown = col('relay-viable', 'bred')
            tag = col(tag, 'bred')
        elif verdict == 'hardened':
            vshown = col('hardened', 'green')
        else:
            vshown = verdict
        if info['note']:
            vshown += ' (%s)' % info['note']

        label = col(self.__endpoint_label(binding), 'yellow')
        proto_col = col(proto_name, 'cyan') if proto_name else ''

        lines = ['  %s %s   %s' % (tag, label, proto_col)]
        lines.append('      iface   : %s' % iface)
        lines.append('      ntlm    : %s' % ('yes' if info['ntlm'] else 'no'))
        lines.append('      levels  : %s' % levels_str)
        lines.append('      floor   : %s' % (info['floor'] or 'none/anon'))
        lines.append('      verdict : %s' % vshown)
        lines.append('')
        return lines


def expand_targets(spec):
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
            hosts.append(token)
    seen, ordered = set(), []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            ordered.append(h)
    return ordered


def parse_creds(prefix):
    domain, username, password = re.compile(
        r'(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?'
    ).match(prefix).groups('')
    return domain or '', username or '', password or ''


def main():
    global USE_COLOR
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
    parser.add_argument('-o', '--output', action='store', dest='output',
                        metavar='FILE', help='also append plain-text results to FILE')
    parser.add_argument('-no-color', action='store_true', dest='no_color',
                        help='disable coloured output')
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose',
                        help='also print unreachable / no-RPC hosts')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init()
    logging.getLogger().setLevel(logging.CRITICAL)

    USE_COLOR = sys.stdout.isatty() and not options.no_color

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

    outfh = None
    if options.output:
        try:
            outfh = open(options.output, 'a')
            outfh.write('\n# rpcauthmap sweep of %d target(s)\n' % len(targets))
        except Exception as e:
            print('[-] Could not open output file: %s' % e)
            outfh = None

    print('[*] Sweeping %d host(s) with %d thread(s)...\n'
          % (len(targets), options.threads))

    def worker(host):
        mapper = RPCAuthMap(
            username=username, password=password, domain=domain,
            hashes=options.hashes, show_all=options.show_all,
            probe_pipes=not options.no_pipes, timeout=options.timeout,
        )
        return host, mapper.scan(host)

    total_relay = hosts_with_hits = hosts_scanned = hosts_quiet = 0
    with ThreadPoolExecutor(max_workers=max(1, options.threads)) as pool:
        futures = [pool.submit(worker, h) for h in targets]
        for fut in as_completed(futures):
            host, (relay_count, lines, status) = fut.result()
            if status == 'scanned':
                hosts_scanned += 1
                if relay_count:
                    hosts_with_hits += 1
                total_relay += relay_count
            else:
                hosts_quiet += 1

            if status == 'scanned' or options.verbose:
                block = '\n'.join(lines)
                with _print_lock:
                    print(block)
                    print('')
                    if outfh:
                        outfh.write(strip_ansi(block) + '\n\n')
                        outfh.flush()

    summary1 = ('[*] Sweep complete: %d target(s) probed; %d live RPC host(s) '
                'scanned, %d unreachable/no-RPC.'
                % (len(targets), hosts_scanned, hosts_quiet))
    summary2 = ('[*] %d relay-viable RPC endpoint(s) found on %d host(s).'
                % (total_relay, hosts_with_hits))
    print(summary1)
    print(summary2)
    if outfh:
        outfh.write(summary1 + '\n' + summary2 + '\n')
        outfh.close()
        print('[*] Plain-text results appended to %s' % options.output)


if __name__ == '__main__':
    main()
