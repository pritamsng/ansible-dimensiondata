#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 Dimension Data
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#   - Aimon Bustardo <aimon.bustardo@dimensiondata.com>
#
from ansible.module_utils.basic import *
from ansible.module_utils.dimensiondata import *
try:
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver
    import libcloud.security
    HAS_LIBCLOUD = True
except:
    HAS_LIBCLOUD = False

# Get regions early to use in docs etc.
dd_regions = get_dd_regions()

DOCUMENTATION = '''
---
module: dimensiondata_public_ip_block
short_description:
    - Create, delete and list public IP blocks.
version_added: '2.1'
author: 'Aimon Bustardo (@aimonb)'
options:
  region:
    description:
      - The target region.
    choices: %s
    default: na
  network_domain:
    description:
      - The target network.
    required: true
  location:
    description:
      - The target datacenter.
    required: true
  block_id:
    description:
      - The first IP of the newtork block.
      - This or 'base_ip' is required when releasing existing block.
    required: false
    default: false
  base_ip:
    description:
      - The first IP of the newtork block.
      - This or 'block_id' Required when releasing existing block.
    required: false
    default: false
  action:
    description:
      - Add or delete public IP block.
      - >
         WARNING: the 'add' action is not idempotent sice there is no way to
         tell what IP will be assigned to us and there are no names for IP
         blocks.
    choices: [add, delete]
    required: true
  verify_ssl_cert:
    description:
      - Check that SSL certificate is valid.
    required: false
    default: true
''' % str(dd_regions)

EXAMPLES = '''
# Add public IP block
- dimensiondata_public_ip_block:
    region: na
    location: NA5
    network_domain: test_network
    action: add
# Delete public IP Block by base IP.
- dimensiondata_public_ip_block:
    region: na
    location: NA5
    network_domain: test_network
    action: delete
    base_ip: 168.128.2.100
# Delete public IP Block by block ID.
- dimensiondata_public_ip_block:
    region: na
    location: NA5
    network_domain: test_network
    action: delete
    block_id: 6288ab1c-0000-0000-0000-b8ca3a5d9ef8
'''

RETURN = '''
public_ip_block:
    description: Dictionary describing the public IP block.
    returned: On success when I(action) is 'add'
    type: dictionary
    contains:
        id:
            description: Block ID.
            type: string
            sample: "8c787000-a000-4050-a215-280893411a7d"
        base_ip:
            description: First IP in block.
            type: string
            sample: "168.128.2.100"
        status:
            description: Status of IP block.
            type: string
            sample: NORMAL
        node_location:
            description: Network location dictionary.
            type: string
            sample: NA1
'''


def ip_block_object_to_dict(block):
    return {'id': block.id, 'base_ip': block.base_ip,
            'status': block.status, 'node_location': block.location.id}


def list_public_ip_blocks(module, driver, network_domain):
    try:
        blocks = driver.ex_list_public_ip_blocks(network_domain)
        if len(blocks) == 0:
            return False
        else:
            return blocks
    except DimensionDataAPIException as e:
        module.fail_json(msg="Error retreving Public IP Blocks: %s" % e)


def add_public_ip_block(module, driver, network_domain):
    try:
        block = driver.ex_add_public_ip_block_to_network_domain(network_domain)
        b_dict = ip_block_object_to_dict(block)
        module.exit_json(changed=True, msg="Success!",
                         public_ip_block=b_dict)
    except DimensionDataAPIException as e:
        module.fail_json(msg="Failed to add public IP block: %s" % str(e))


def delete_public_ip_block(module, driver, network_domain, block_id=False,
                           base_ip=False):

    # Block ID given, try to use it.
    if block_id is not 'False':
        block = False
        try:
            block = driver.ex_get_public_ip_block(block_id)
        except DimensionDataAPIException as e:
            # 'UNEXPECTED_ERROR' should be removed once upstream bug is fixed.
            # Currently any call to ex_get_public_ip_block where the block does
            # not exist will return UNEXPECTED_ERROR rather than
            # 'RESOURCE_NOT_FOUND'.
            if e.code == "RESOURCE_NOT_FOUND" or e.code == 'UNEXPECTED_ERROR':
                module.exit_json(changed=False, msg="Public IP Block does " +
                                 "not exist")
            else:
                module.fail_json(msg="Unexpected error while retrieving " +
                                     "block: %s" % e.code)
    # Block ID not given, try to use base_ip.
    else:
        blocks = list_public_ip_blocks(module, driver, network_domain)
        if blocks is not False:
            block = filter(lambda x: x.base_ip == base_ip, blocks)[0]
        else:
            module.exit_json(changed=False, msg="IP block starting with " +
                             "'%s' does not exist." % base_ip)
    # Now that we have the block, try to dselete it.
    if block is not False:
        try:
            driver.ex_delete_public_ip_block(block)
            module.exit_json(changed=True, msg="Deleted!")
        except DimensionDataAPIException as e:
            module.fail_json(msg="Error deleting Public Ip Block: %s" % e)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=dd_regions),
            network_domain=dict(required=True, type='str'),
            location=dict(required=True, type='str'),
            base_ip=dict(default=False, type='str'),
            block_id=dict(default=False, type='str'),
            action=dict(required=True, choices=['add', 'delete']),
            verify_ssl_cert=dict(required=False, default=True, type='bool')
        )
    )

    if not HAS_LIBCLOUD:
        module.fail_json(msg='libcloud is required for this module.')

    # set short vars for readability
    credentials = get_credentials()
    if credentials is False:
        module.fail_json(msg="User credentials not found")
    user_id = credentials['user_id']
    key = credentials['key']
    region = 'dd-%s' % module.params['region']
    network_domain = module.params['network_domain']
    location = module.params['location']
    base_ip = module.params['base_ip']
    block_id = module.params['block_id']
    verify_ssl_cert = module.params['verify_ssl_cert']
    action = module.params['action']

    # Instantiate driver
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert
    DimensionData = get_driver(Provider.DIMENSIONDATA)
    driver = DimensionData(user_id, key, region=region)

    # get the network domain object
    network_domain_obj = get_network_domain(driver, network_domain, location)
    if action == 'delete':
        delete_public_ip_block(module, driver, network_domain_obj, block_id,
                               base_ip)
    elif action == 'add':
        add_public_ip_block(module, driver, network_domain_obj)
    else:
        module.fail_json(msg="Unexpected action " +
                             "'%s' is not 'delete' or 'add'" % action)

if __name__ == '__main__':
    main()
