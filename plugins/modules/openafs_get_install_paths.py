#!/usr/bin/python
# Copyright (c) 2020, Sine Nomine Associates
# BSD 2-Clause License

ANSIBLE_METADATA = {
    'metadata_version': '1.1.',
    'status': ['preview'],
    'supported_by': 'community',
}

DOCUMENTATION = r'''
---
module: openafs_get_install_paths

short_description: Detect installation paths

description:
  - Gather the paths to installed OpenAFS programs from the
    installed packages

options:
  package_mgr_type:
    description:
      - The package manager type on this remote node.
      - Supported values are C(rpm) and C(apt)
    default: rpm

author:
  - Michael Meffie
'''

EXAMPLES = r'''
- name: Get installation paths
  openafs_contrib.openafs.openafs_get_install_paths:
    package_manager_type: apt
  register: install_results
'''

import os                   # noqa: E402
import fnmatch              # noqa: E402
import logging              # noqa: E402
import logging.handlers     # noqa: E402
import pprint               # noqa: E402

from ansible.module_utils.basic import AnsibleModule   # noqa: E402

module_name = os.path.basename(__file__).replace('.py', '')
log = logging.getLogger(module_name)


def setup_logging():
    level = logging.INFO
    fmt = '%(levelname)s %(name)s %(message)s'
    address = '/dev/log'
    if not os.path.exists(address):
        address = ('localhost', 514)
    facility = logging.handlers.SysLogHandler.LOG_USER
    formatter = logging.Formatter(fmt)
    handler = logging.handlers.SysLogHandler(address, facility)
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(level)


package_managers = {
    'rpm': {
        'query_packages': ['/usr/bin/rpm', '--query', '--all'],
        'query_files': ['/usr/bin/rpm', '--query', '--list'],
        'dirs': {
            'afsbosconfigdir': '/usr/afs/local',
            'afsconfdir': '/usr/afs/etc',
            'afsdbdir': '/usr/afs/db',
            'afslocaldir': '/usr/afs/local',
            'afslogdir': '/usr/afs/logs',
            'afssrvdir': '/usr/afs/bin',
            'viceetcdir': '/usr/vice/etc',
        },
        'aliases': {},
    },
    'apt': {
        'query_packages': [
            '/usr/bin/dpkg-query', '--show', '--showformat', '${Package}\\n'
        ],
        'query_files': ['/usr/bin/dpkg-query', '--listfiles'],
        'dirs': {
            'afsbosconfigdir': '/etc/openafs',
            'afsconfdir': '/etc/openafs/server',
            'afsdbdir': '/var/lib/openafs/db',
            'afslocaldir': '/var/lib/openafs/local',
            'afslogdir': '/var/log/openafs',
            'afssrvdir': '/usr/lib/openafs',
            'viceetcdir': '/etc/openafs',
        },
        'aliases': {
            'pagsh.openafs': 'pagsh',
        }
    },
}


def list_files(module, pm):
    """
    List installed files.
    """
    packages = []
    rc, out, err = module.run_command(pm['query_packages'], check_rc=True)
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('openafs'):
            packages.append(line)
    if packages:
        rc, out, err = \
            module.run_command(pm['query_files'] + packages, check_rc=True)
        for line in out.splitlines():
            line = line.strip()
            if line and os.path.exists(line):
                yield line


def main():
    setup_logging()
    results = dict(
        changed=False,
        bins={},
        dirs={},
    )
    module = AnsibleModule(
        argument_spec=dict(
            package_manager_type=dict(choices=['rpm', 'apt'], default='rpm'),
        ),
        supports_check_mode=False,
    )
    log.info('Parameters: %s', pprint.pformat(module.params))

    pm = package_managers[module.params['package_manager_type']]

    # Helper to exclude libraries and build artifacts.
    def exclude(f):
        for pattern in ('/*/lib*.so*', '/usr/src/*'):
            if fnmatch.fnmatch(f, pattern):
                return True
        return False

    # Gather installed commands.
    for f in list_files(module, pm):
        basename = os.path.basename(f)
        name = pm['aliases'].get(basename, basename)
        if exclude(f):
            continue
        if os.path.isfile(f) \
           and os.access(f, os.X_OK) \
           and '.build-id' not in f \
           and results['bins'].get(name) != f:
            results['bins'][name] = f

    # Add package specific directory paths. Ideally we would query the
    # installed binaries for the paths, but we don't have a good way to do that
    # yet (e.g. -V option), so punt and assume the the paths based on the
    # package type.
    results['dirs'] = pm['dirs']

    log.info('Results: %s', pprint.pformat(results))
    module.exit_json(**results)


if __name__ == '__main__':
    main()
