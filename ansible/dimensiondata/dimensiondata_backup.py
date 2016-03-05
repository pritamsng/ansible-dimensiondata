#!/usr/bin/python
DOCUMENTATION = '''
---
module: dimensiondata_backup
short_description: enable or disable backups for a host
description:
    - Creates, enables or disables backups for a host in the Dimension Data Cloud
version_added: "1.9"
options:
  state:
    description:
      - the state you want the hosts to be in
    required: false
    default: present
    aliases: []
    choices: ['present', 'absent']
  server_ids:
    description:
      - A list of server ids to work on
    required: false
    default: null
    aliases: ['server_id']
  name:
    description:
      - The name of the server you want to work on
    required: false
    default: null
    aliases: []
  image:
    description:
      - The image name to provision with
    required: false
    default: null
    aliases: []
  image_id:
    description:
      - The image_id to provisiong with
    required: false
    default: null
    aliases: []
  vlan:
    description:
      - The name of the vlan to provision to
    required: false
    default: null
    aliases: []
  vlan_id:
    description:
      - The vlan_id to provision to
    required: false
    default: null
    aliases: []
  network:
    description:
      - The name of the network to provision to
    required: false
    default: null
    aliases: []
  network_id:
    description:
      - The network_id to provision to
    required: false
    default: null
    aliases: []
  network_domain:
    description:
      - The name of the network domain to provision to
    required: false
    default: null
    aliases: []
  network_domain_id:
    description:
      - The network_domain_id to provision to
    required: false
    default: null
    aliases: []
  admin_password:
    description:
      - The administrator account password for a new server
    required: false
    default: null
    aliases: []
  description:
    description:
      - The description for the new node
    required: false
    default: null
    aliases: []
  memory_gb:
    description:
      - The amount of memory for the new host to have in Gb
    required: false
    default: null
    aliases: []
  unique_names:
    description:
      - By default Dimension Data allows the same name for multiple servers this will make sure we don't create a new server if the name already exists
    required: false
    default: 'no'
    aliases: []
    choices: ['yes', 'no']

author:
    - "Jeff Dunham (@jadunham1)"
'''

EXAMPLES = '''
# Note: These examples don't include authorization.  You can set these by exporting DIDATA_USER and DIDATA_PASSWORD environment variables like:
# export DIDATA_USER=<username>
# export DIDATA_PASSWORD=<password>

# Basic create node example

- didata:
    vlan_id: '{{ vlan_id }}'
    network_domain_id: '{{ network_domain_id }}'
    image: 'RedHat 7 64-bit 2 CPU'
    name: ansible-test-image
    admin_password: fakepass
'''
import os
import json

HAS_LIBCLOUD = True
try:
    from libcloud.compute.drivers.dimensiondata import DimensionDataNodeDriver
    from libcloud.common.dimensiondata import DEFAULT_REGION
except ImportError:
    HAS_LIBCLOUD = False

def module_key_die_if_none(module, key):
    v = module.params[key]
    if v is None:
        module.fail_json(msg='Unable to load %s' % key)
    return v


def get_image_id(client, module, location):
    if module.params['image_id'] is not None:
        return module.params['image_id']
    if module.params['image'] is None:
        module.fail_json(msg='Need to specify either an image_id or image to create a node')

    image_match_name = module.params['image']
    images = client.list_images(location)
    images.extend( client.ex_list_customer_images(location) )

    matched_images = list(filter(lambda x: x.name == image_match_name, images))

    if len(matched_images) < 1:
        module.fail_json(msg='No images matched this name')
    elif len(matched_images) > 1:
        module.fail_json(msg='Multile images matched this please specify one of the image ids')

    return matched_images[0].id


def create_node(client, module):
    changed = False
    name = module_key_die_if_none(module, 'name')
    if module.params['unique_names']:
        node_list = client.list_nodes(ex_name=name)
        if len(node_list) >= 1:
            return (changed, [node.id for node in node_list])

    admin_password = module_key_die_if_none(module, 'admin_password')
    vlan_id = module_key_die_if_none(module, 'vlan_id')
    network_id = module.params['network_id']
    network_domain_id = module.params['network_domain_id']
    if not network_domain_id and not network_id:
        moduule.fail_json(msg='Need either a network_id (MCP1.0) or network_domain_id (MCP_2.0) to create a server')

    dd_vlan = client.ex_get_vlan(vlan_id)
    image_id = get_image_id(client, module, dd_vlan.location.id)
    node = client.create_node(name, image_id, admin_password,
                       module.params['description'],
                       ex_network=network_id,
                       ex_network_domain=network_domain_id,
                       ex_vlan=vlan_id,
                       ex_memory_gb=module.params['memory_gb'])
    return (True, node.id)



def stoporstart_servers(client, module, desired_state):
    changed = False

    servers = module_key_die_if_none(module, 'server_ids')
    node_list = []
    for server in servers:
        node = client.ex_get_node_by_id(server)
        node_list.append({
            'id': node.id,
            'prev_state': node.state,
            'desired_state': desired_state
        })
        if node.state == 'terminated':
            node.state = 'stopped'
        if desired_state != node.state:
            if desired_state == 'running':
                client.ex_start_node(node)
                changed = True
            elif desired_state == 'stopped':
                client.ex_shutdown_graceful(node)
                changed = True

    return (changed, node_list)

def core(module):
    try:
        username = os.environ['DIDATA_USER']
        password = os.environ['DIDATA_PASSWORD']
    except KeyError, e:
        module.fail_json(msg='unable to find key %s' % e.message)

    if not username or not password:
        module.fail_json(msg='here unable to find username %s and password %s')

    try:
        region = os.environ['REGION']
    except KeyError:
        region = DEFAULT_REGION

    client = DimensionDataNodeDriver(username, password, region)
    state = module.params['state']
    if state == 'present':
        return enable_backup(client, module)
    elif state == 'absent':
        return remove_backup(client, module)
    else:
        module.fail_json(msg='Unhandled state transition')


def main():
    module = AnsibleModule(
        argument_spec = dict(
            state = dict(default='present', choices=['present', 'absent']),
            server_ids = dict(type='list', aliases=['server_id']),
            plan = dict(choices=['ADVANCED', 'ESSENTIALS', 'ENTERPRISE'])
        )
    )
    if not HAS_LIBCLOUD:
        module.fail_json(msg='libcloud >= 1.0.0pre required for this module')

    try:
        (changed, data) = core(module)
    except (Exception), e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=changed, instances=data)

from ansible.module_utils.basic import *

if __name__ == '__main__':
        main()
