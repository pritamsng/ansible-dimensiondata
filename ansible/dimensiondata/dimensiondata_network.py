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
from ansible.module_utils.dimensiondatacloud import *
try:
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver
    import libcloud.security
    HAS_LIBCLOUD = True
except:
    HAS_LIBCLOUD = False
import json

DOCUMENTATION = '''
---
module: dimensiondata_network
short_description:
    - Create, update, and delete MCP 1.0 & 2.0 networks
version_added: '2.1'
author: 'Aimon Bustardo (@aimonb)'
options:
  region:
    description:
      - The target region.
    choices: ['na', 'eu', 'au', 'af', 'ap', 'latam', 'canada', 'canberra', 'id', 'in', 'il', 'sa']
    default: na
  location:
    description:
      - The target datacenter.
    required: true
  name:
    description:
      - The name of the network domain to create.
    required: true
  description:
    description:
      - Additional description of the network domain.
    required: false
    default: null
  service_plan:
    description:
      - The service plan, either “ESSENTIALS” or “ADVANCED”.
      - MCP 2.0 Only.
    choices: [ESSENTIALS, ADVANCED]
    default: ADVANCED
  verify_ssl_cert:
    description:
      - Check that SSL certificate is valid.
    required: false
    default: true
  state:
    description:
      - Should the resource be present or absent.
    choices: [present, absent]
    default: present
'''

EXAMPLES = '''
# Create an MCP 1.0 network
- dimensiondata_network:
    region: na
    location: NA5
    name: mynet
# Create an MCP 2.0 network
- dimensiondata_network:
    region: na
    location: NA9
    name: mynet
    service_plan: ADVANCED
# Delete a network
- dimensiondata_network:
    region: na
    location: NA1
    name: mynet
    state: absent
'''

RETURN = '''
network:
    description: Dictionary describing the network.
    returned: On success when I(state) is 'present'
    type: dictionary
    contains:
        id:
            description: Network ID.
            type: string
            sample: "8c787000-a000-4050-a215-280893411a7d"
        name:
            description: Network name.
            type: string
            sample: "My network"
        description:
            description: Network description.
            type: string
            sample: "My network description"
        location:
            description: Datacenter location.
            type: dictionary
            sample:
                id: NA3
                name: US - West
                country: US
                driver: DimensionData
        status:
            description: Network status. (MCP 2.0 only)
            type: string
            sample: NORMAL
        private_net:
            description: Private network subnet. (MCP 1.0 only)
            type: string
            sample: "10.2.3.0"
        multicast:
            description: Multicast enabled? (MCP 1.0 only)
            type: boolean
            sample: false
'''


def network_obj_to_dict(network, version):
    network_dict = dict(id=network.id, name=network.name,
                        description=network.description)
    if version == '1.0':
        network_dict['private_net'] = network.private_net
        network_dict['multicast'] = network.multicast
        network_dict['status'] = None
        network_dict['location'] = dict(id=network.location.id,
                                        name=network.location.name,
                                        country=network.location.country,
                                        driver=network.location.driver)
    else:
        network_dict['private_net'] = None
        network_dict['multicast'] = None
        network_dict['status'] = network.status
        network_dict['location'] = network.location
    return network_dict


def get_mcp_version(driver, location):
    # Get location to determine if MCP 1.0 or 2.0
    location = driver.ex_get_location_by_id(location)
    if 'MCP 2.0' in location.name:
        return '2.0'
    return '1.0'


def create_network(module, driver, mcp_version, location,
                   name, description, service_plan=None):

    # Make sure service_plan argument is defined
    if mcp_version == '2.0' and state == 'present' and \
            'service_plan' not in module.params:
        module.fail_json('service_plan required when creating netowrk and ' +
                         'location is MCP 2.0')
    service_plan = module.params['service_plan']

    # Create network
    try:
        if mcp_version == '1.0':
            res = driver.ex_create_network(location, name,
                                           description=description)
        else:
            res = driver.ex_create_network_domain(location, name,
                                                  service_plan,
                                                  description=description)
    except Exception as e:
        module.fail_json(msg="Failed to create new network: %s" % str(e))
    msg = json.dump(network_obj_to_dict(res, mcp_version))
    module.exit_json(changed=True, msg=msg)


def delete_network(module, driver, matched_network, mcp_version):
    try:
        if mcp_version == '1.0':
            res = driver.ex_delete_network(matched_network[0])
        else:
            res = driver.ex_delete_network_domain(matched_network[0])
        if res is True:
            module.exit_json(changed=True,
                             msg="Deleted network with id %s" %
                             matched_network[0].id)
        module.fail_json("Unexpected failure deleting network with " +
                         "id %s", matched_network[0].id)
    except Exception as e:
        module.fail_json(msg="Failed to delete network: %s" % str(e))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=['na', 'eu', 'au', 'af', 'ap',
                                               'latam', 'canada', 'canberra',
                                               'id', 'in', 'il', 'sa']),
            location=dict(required=True, type='str'),
            name=dict(required=True, type='str'),
            description=dict(required=False, type='str'),
            service_plan=dict(default='ADVANCED', choices=['ADVANCED',
                              'ESSENTIALS']),
            state=dict(default='present', choices=['present', 'absent']),
            verify_ssl_cert=dict(required=False, default=True, type='bool')
            )
    )

    if not HAS_LIBCLOUD:
        module.fail_json(msg='libcloud is required for this module.')

    # set short vars for readability
    credentials = get_credentials()
    if credentials is False:
        module.fail_json("User credentials not found")
    user_id = credentials['user_id']
    key = credentials['key']
    region = 'dd-%s' % module.params['region']
    location = module.params['location']
    name = module.params['name']
    description = module.params['description']
    verify_ssl_cert = module.params['verify_ssl_cert']
    state = module.params['state']

    # Instantiate driver
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert
    DimensionData = get_driver(Provider.DIMENSIONDATA)
    driver = DimensionData(user_id, key, region=region)

    # Get MCP API Version
    mcp_version = get_mcp_version(driver, location)

    # Get network list
    if mcp_version == '1.0':
        networks = driver.list_networks(location=location)
    else:
        networks = driver.ex_list_network_domains(location=location)
    matched_network = filter(lambda x: x.name == name, networks)

    # Ensure network state
    if state == 'present':
        # Network already exists
        if matched_network:
            module.exit_json(changed=False,
                             network=str(network_obj_to_dict(
                                         matched_network[0], mcp_version)))
        create_network(module, driver, mcp_version, location, name,
                       description, service_plan)
    elif state == 'absent':
        # Destroy network
        if matched_network:
            delete_network(module, driver, matched_network, mcp_version)
        else:
            module.exit_json(changed=False, msg="Network does not exist")
    else:
        fail_json(msg="Requested state was " +
                  "'%s'. State must be 'absent' or 'failed'" % state)

main()
