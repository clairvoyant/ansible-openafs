#!/usr/bin/python

# Copyright (c) 2021, Sine Nomine Associates
# BSD 2-Clause License

ANSIBLE_METADATA = {
    'metadata_version': '1.1.',
    'status': ['preview'],
    'supported_by': 'community',
}

DOCUMENTATION = r'''
---
module: openafs_gethostbyname_check

short_description:

description:

options:

author:
  - Michael Meffie
'''

EXAMPLES = r'''
'''

RETURN = r'''
'''

import os                      # noqa: E402
import platform                # noqa: E402
import pprint                  # noqa: E402
import socket                  # noqa: E402
import struct                  # noqa: E402

from ansible.module_utils.basic import AnsibleModule  # noqa: E402
from ansible.module_utils.common.process import get_bin_path
from ansible_collections.openafs_contrib.openafs.plugins.module_utils.common import Logger  # noqa: E402, E501
from ansible_collections.openafs_contrib.openafs.plugins.module_utils.common import execute  # noqa: E402, E501

# Globals
module_name = os.path.basename(__file__).replace('.py', '')
log = None
module = None
results = None


def solaris_getifaddrs():
    ifaddrs = {}
    ipadm = get_bin_path('ip', required='True')
    output = execute('%(ipadm)s show-addr -p -o addrobj,addr' % locals())
    for line in output.splitlines():
        addrobj, addrmask = line.split(':', 1)
        interface, version = addrobj.split('/', 1)
        if version == 'v4' and not addrmask.startswith('127'):
            addr, mask = addrmask.split('/', 1)
            ifaddrs[interface] = addr
    return ifaddrs


def linux_getifaddrs():
    ifaddrs = {}
    ip = get_bin_path('ip', required='True')
    output = execute('%(ip)s -o addr' % locals())
    for line in output.splitlines():
        fields = line.split()
        if fields[2] == 'inet' and not fields[3].startswith('127'):
            interface = fields[1]
            addr, mask = fields[3].split('/', 1)
            ifaddrs[interface] = addr
    return ifaddrs


uname = platform.system()
if uname == 'Linux':
    hosts_file_path = '/etc/hosts'
    getifaddrs = linux_getifaddrs
elif uname == 'SunOS':
    getifaddrs = solaris_getifaddrs
    hosts_file_path = '/etc/inet/hosts'
else:
    raise NotImplementedError('Unsupported platform: %s' % uname)


def inet_to_int(address):
    """
    Convert ipv4 dotted string to int.
    """
    return struct.unpack('!L', socket.inet_aton(address))[0]


def int_to_inet(i):
    """
    Convert int to ipv4 dotted string.
    """
    return socket.inet_ntoa(struct.pack('!L', i))


def in_network(address, network):
    """
    Returns True if address is in subnetwork.
    """
    address = inet_to_int(address)
    fields = network.split('/')
    if len(fields) != 2:
        raise ValueError('Invalid network: %s' % network)
    netaddr = inet_to_int(fields[0])
    prefix = int(fields[1])
    if not (0 < prefix < 32):
        raise ValueError('prefix is out of range: %s' % network)

    # Calculate the netmask.
    n = (1 << (32 - prefix))    # Number of addresses in the subnet.
    netmask = 0xffffffff & ~(n - 1)

    # Calculate network address range.
    first = netaddr & netmask
    last = netaddr | (0xffffffff & ~netmask)

    # Check if address is in the network range, excluding the network and
    # broadcast addresses.
    return (first < address < last)


def netmatch(address, entry):
    """
    Returns true if address matches netinfo/netrict entry.
    """
    if entry.startswith('f'):
        if '/' in entry:
            raise ValueError('Invalid entry: %s' % entry)
        entry = entry.replace('f', '')
    if '/' in entry:
        if in_network(address, entry):
            return True
    else:
        entry = inet_to_int(entry)
        address = inet_to_int(address)
        if address == entry:
            return True
    return False


def netinclude(netinfo, addresses):
    """
    Filter address list with netinfo entries.
    """
    if not netinfo:
        return list(addresses)
    output = []
    for address in addresses:
        for entry in netinfo:
            if netmatch(address, entry):
                output.append(address)
    return output


def netexclude(netrestrict, addresses):
    """
    Filter address list with netrestrict entries.
    """
    if not netrestrict:
        return list(addresses)
    output = []
    for address in addresses:
        for entry in netrestrict:
            if not netmatch(address, entry):
                output.append(address)
    return output


def netfilter(addresses, netinfo, netrestrict):
    """
    Filter address list with netinfo and netrestrict entries.
    """
    output = netexclude(netrestrict, netinclude(netinfo, addresses))
    return output

'''
def gethostbyname_check():
    hostname = socket.gethostname()
    address = socket.gethostbyname(hostname)
    ifaddrs = getifaddrs()

    log.info('ifaddrs=%s', pprint.pformat(ifaddrs))
    ok = address in list(ifaddr.values())
    if ok:
        log.info('gethostbyname check passed.')
    else:
        log.warning('gethostbyname check failed; address=%s, ifaddrs=%s',
            address, pprint.pformat(ifaddrs))

    results['ok'] = ok
    results['hostname'] = hostname
    results['address'] = address
    results['ifaddrs'] = ifaddrs
    results['ifaddrs_len'] = len(ifaddrs)
    return check


def change_hosts_file():
    hostname = socket.gethostname()
    with open(hosts_file_path) as f:
        hosts = f.read()
    log.info('%s: %s', hosts_file_path, hosts)


def xyzzy(hosts, hostname, address):
    if address.startswith('127.'):
        raise ValueError('cant use loopback')
    found = False
    output = []
    for line in hosts.splitlines():
        m = re.match(r'^\s*(\d+\.\d+\.\d+\.\d+)\s*(.*)\s*', line)
        if m:
            addr = m.group(1)
            names = m.group(2).split()
            if hostname in names:
                if addr == address:
                    found = True
                else:
                    names.remove(hostname)
                    if not names:
                        continue
                    line = '%s %s' % (addr, ' '.join(names))
        output.append(line)
    if not found:
        output.append('%s %s' % (address, hostname))
    return '\n'.join(output)


def main():
    global log
    global results
    global module
    results = dict(
        changed=False,
    )
    module = AnsibleModule(
        argument_spec=dict(
            enable_change_hosts_file=dict(type='bool', default=False),
            netinfo=dict(type='list', default=None),
            netrestrict=dict(type='list', default=None),
        ),
        supports_check_mode=False,
    )
    log = Logger(module_name)
    log.info('Starting %s', module_name)
    log.info('Parameters: %s', pprint.pformat(module.params))

    enable_change_hosts_file = module.params['enable_change_hosts_file']
    netinfo = module.params['netinfo']
    netrestrict = module.params['netrestrict']

    hostname = socket.gethostname()
    address = socket.gethostbyname(hostname)
    ifaddrs = getifaddrs()
    pubaddrs = netfilter(ifaddrs.values(), netinfo, netrestrict)
    default_addr = pubaddrs[0] if len(pubaddrs) > 0 else None

    ok = address in pubaddrs
    if not ok:
        pass

    with open(hosts_file_path) as f:
        hosts = f.read()

    with open(hosts_file_path, 'w') as f:
        f.write(xyzzy(hosts, hostname, default_address))

    module.exit_json(**results)


if __name__ == '__main__':
    main()
