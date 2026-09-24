#!/usr/bin/env python3
# rpcauthmap.py
#
# RPC endpoint enumerator + NTLM auth / RPC-layer protection prober
# (Impacket / Python 3). Based on CORE Security Technologies' rpcdump.py.
#
# For each registered interface it:
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
# Caveat: this tests acceptance at BIND time. A server can, in principle, accept
# a low-level bind and enforce a higher level only at call time on specific
# opnums. Confirm anything ambiguous with a real authenticated call or a capture.
#
# For authorized security testing only.

import sys
import logging
import argparse

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

    def dump(self, target):
        entries = self.__fetch_endpoints(target)
        if not entries:
            print('[-] No endpoints returned by the endpoint mapper.')
            return

        seen = set()
        results = []
        for entry in entries:
            floors = entry['tower']['Floors']
            iface = str(floors[0])                       # "uuid vX.Y"
            binding = epm.PrintStringBinding(floors, target)
            annotation = self.__clean_annotation(entry['annotation'])
            key = (iface, binding)
            if key in seen:
                continue
            seen.add(key)
            results.append((iface, binding, annotation))

        print('[*] Probing %d unique endpoint(s) on %s...\n'
              % (len(results), target))

        relay_candidates = 0
        for iface, binding, annotation in results:
            info = self.__probe(iface, binding)
            if info['verdict'] == 'relay-viable':
                relay_candidates += 1
            # Default view: NTLM-relevant endpoints only. -all shows the rest.
            if info['ntlm'] or self.__show_all:
                self.__print_entry(iface, binding, annotation, info)

        print('\n[*] %d endpoint(s) accepted an authenticated UNSIGNED bind '
              '(relay-viable RPC destinations).' % relay_candidates)

    def __fetch_endpoints(self, target):
        rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s' % target)
        rpctransport.set_dport(135)
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
        except Exception as e:
            print('[-] Endpoint mapper query failed: %s' % e)
            return []

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

        # Try each level, remember which succeed.
        for name, level, authenticated in AUTH_LEVELS:
            ok, _detail = self.__try_bind(binding, iface_bin, level, authenticated)
            base['accepted'][name] = ok

        # NTLM is "spoken" if any authenticated level bound.
        auth_ok = {n: base['accepted'][n] for n in ('connect', 'integrity', 'privacy')}
        base['ntlm'] = any(auth_ok.values())

        # Lowest accepted AUTHENTICATED level is the enforced floor.
        for name in ('connect', 'integrity', 'privacy'):
            if base['accepted'][name]:
                base['floor'] = name
                break

        if base['floor'] == 'connect':
            base['verdict'] = 'relay-viable'          # unsigned auth accepted
        elif base['floor'] in ('integrity', 'privacy'):
            base['verdict'] = 'hardened'              # signing/sealing required
        elif base['accepted'].get('none'):
            base['verdict'] = 'anon-only'             # bound only without auth
        else:
            base['verdict'] = 'no-bind'               # nothing bound

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
    def __clean_annotation(annotation):
        if isinstance(annotation, bytes):
            annotation = annotation.decode('utf-8', errors='replace')
        return (annotation or '').rstrip('\x00').strip()

    @staticmethod
    def __print_entry(iface, binding, annotation, info):
        tag = {
            'relay-viable': '[+]',   # authenticated unsigned bind accepted
            'hardened':     '[-]',   # integrity/privacy enforced
            'anon-only':    '[a]',   # only unauthenticated bind succeeded
            'no-bind':      '[x]',   # nothing bound
            'skipped':      '[ ]',
            'error':        '[!]',
        }.get(info['verdict'], '[?]')

        acc = info['accepted']
        levels_str = ', '.join(
            '%s=%s' % (n, 'ok' if acc.get(n) else '-')
            for n in ('none', 'connect', 'integrity', 'privacy')
        )

        print('%s %s' % (tag, binding))
        print('    Interface : %s' % iface)
        if annotation:
            print('    Service   : %s' % annotation)
        print('    NTLM      : %s' % ('yes' if info['ntlm'] else 'no'))
        print('    Levels    : %s' % levels_str)
        print('    Floor     : %s' % (info['floor'] or 'none/anon'))
        print('    Verdict   : %s%s' % (
            info['verdict'], ' (%s)' % info['note'] if info['note'] else ''))
        print('')


def parse_target(target):
    import re
    domain, username, password, address = re.compile(
        r'(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)'
    ).match(target).groups('')
    return domain or '', username or '', password or '', address


def main():
    print(version.BANNER)
    parser = argparse.ArgumentParser(
        add_help=True,
        description='Enumerate RPC endpoints; report NTLM acceptance and the '
                    'enforced RPC auth level (integrity/privacy) per interface.'
    )
    parser.add_argument('target', action='store',
                        help='[[domain/]username[:password]@]<target>')
    parser.add_argument('-all', '--all', action='store_true', dest='show_all',
                        help='show every endpoint, not just NTLM-capable ones')
    parser.add_argument('-no-pipes', action='store_true', dest='no_pipes',
                        help='do not probe named-pipe (ncacn_np) bindings')
    parser.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH',
                        help='NTLM hashes, format LMHASH:NTHASH')
    parser.add_argument('-timeout', action='store', type=int, default=5,
                        help='per-attempt connect timeout in seconds (default 5)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init()
    logging.getLogger().setLevel(logging.CRITICAL)   # silence impacket chatter

    domain, username, password, address = parse_target(options.target)
    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass('Password:')

    mapper = RPCAuthMap(
        username=username, password=password, domain=domain,
        hashes=options.hashes, show_all=options.show_all,
        probe_pipes=not options.no_pipes, timeout=options.timeout,
    )
    mapper.dump(address)


if __name__ == '__main__':
    main()
