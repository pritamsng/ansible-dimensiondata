#!/usr/bin/python
from ansible.module_utils.basic import *
from ansible.module_utils.dimensiondata import *

HAS_LIBCLOUD = True
try:
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver
    import libcloud.security
except ImportError:
    HAS_LIBCLOUD = False

# Get regions early to use in docs etc.
dd_regions = get_dd_regions()

DOCUMENTATION = '''
---
module: didata
short_description: create, terminate, start or stop an server in dimensiondata
description:
    - Creates, terminates, starts or stops servers in the Dimension Data Cloud
version_added: "1.9"
options:
  region:
    description:
      - The target region.
    choices: %s
    default: na
  state:
    description:
      - the state you want the hosts to be in
    required: false
    default: present
    aliases: []
    choices: ['present', 'absent', 'running', 'stopped']
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
      - By default Dimension Data allows the same name for multiple servers
        this will make sure we don't create a new server if the name
        already exists
    required: false
    default: 'no'
    aliases: []
    choices: ['yes', 'no']
  verify_ssl_cert:
    description:
      - Check that SSL certificate is valid.
    required: false
    default: true
  wait:
    description:
      - Should we wait for the task to complete before moving onto the next.
    required: false
    default: false
  wait_time:
    description:
      - Only applicable if wait is true.
        This is the amount of time in seconds to wait
    required: false
    default: 600
  wait_poll_interval:
    description:
      - The amount to time inbetween polling for task completion
    required: false
    default: 2

author:
    - "Jeff Dunham (@jadunham1)"
''' % str(dd_regions)

EXAMPLES = '''
# Note: These examples don't include authorization.
#       You can set these by exporting DIDATA_USER and DIDATA_PASSWORD var:
# export DIDATA_USER=<username>
# export DIDATA_PASSWORD=<password>

# Basic create node example

- dimensiondata:
    vlan_id: '{{ vlan_id }}'
    network_domain_id: '{{ network_domain_id }}'
    image: 'RedHat 7 64-bit 2 CPU'
    name: ansible-test-image
    admin_password: fakepass

# Ensure servers are running and wait for it to come up
- dimensiondata:
    state: running
    server_ids: '{{ server_ids }}'
    wait: yes

# Ensure servers are stopped and wait for them to stop

- dimensiondata:
    state: stopped
    server_ids: '{{ server_ids }}'
    wait: yes
'''


def module_key_die_if_none(module, key):
    v = module.params[key]
    if v is None:
        module.fail_json(msg='Unable to load %s' % key)
    return v


def get_image_id(client, module, location):
    if module.params['image_id'] is not None:
        return module.params['image_id']
    if module.params['image'] is None:
        module.fail_json(msg='Need to specify either an image_id or'
                             'image to create a node')

    image_match_name = module.params['image']
    images = client.list_images(location)
    images.extend(client.ex_list_customer_images(location))

    matched_images = list(filter(lambda x: x.name == image_match_name, images))

    if len(matched_images) < 1:
        module.fail_json(msg='No images matched this name')
    elif len(matched_images) > 1:
        module.fail_json(msg='Multile images matched this please'
                             ' specify a single unique image id')

    return matched_images[0].id


def node_to_node_obj(node):
    node_obj = {}
    node_obj['id'] = node.id
    node_obj['ipv6'] = node.extra['ipv6']
    node_obj['os_type'] = node.extra['OS_type']
    node_obj['private_ipv4'] = node.private_ips
    node_obj['public_ipv4'] = node.public_ips
    node_obj['location'] = node.extra['datacenterId']
    node_obj['state'] = node.state
    # Password object will only be set if the password is randomly generated
    if 'password' in node.extra:
        node_obj['password'] = node.extra['password']
    return node_obj


def create_node(client, module):
    changed = False
    name = module_key_die_if_none(module, 'name')
    if module.params['unique_names']:
        node_list = client.list_nodes(ex_name=name)
        if len(node_list) >= 1:
            return (changed, [node_to_node_obj(node) for node in node_list])

    admin_password = module.params.get('admin_password')
    vlan_id = module_key_die_if_none(module, 'vlan_id')
    network_id = module.params['network_id']
    network_domain_id = module.params['network_domain_id']
    if not network_domain_id and not network_id:
        module.fail_json(msg='Need either a network_id (MCP1.0) or '
                             'network_domain_id (MCP_2.0) to create a server')

    dd_vlan = client.ex_get_vlan(vlan_id)
    image_id = get_image_id(client, module, dd_vlan.location.id)
    node = client.create_node(name, image_id, admin_password,
                              module.params['description'],
                              ex_network=network_id,
                              ex_network_domain=network_domain_id,
                              ex_vlan=vlan_id,
                              ex_memory_gb=module.params['memory_gb'])
    if module.params['wait']:
        node = wait_for_server_state(client, module, node.id, 'running')
    node_obj = node_to_node_obj(node)
    return (True, [node_obj])


def wait_for_server_state(client, module, server_id, state_to_wait_for):
    try:
        return client.connection.wait_for_state(
            state_to_wait_for, client.ex_get_node_by_id,
            module.params['wait_poll_interval'],
            module.params['wait_time'], server_id
        )
    except DimensionDataAPIException as e:
        module.fail_json(msg='Server did not reach % state in time: %s'
                         % (state, e.msg))


def stoporstart_servers(client, module, desired_state):
    changed = False

    servers = module_key_die_if_none(module, 'server_ids')
    node_list = []
    for server in servers:
        node = client.ex_get_node_by_id(server)
        if node.state == 'terminated':
            node.state = 'stopped'
        if desired_state != node.state:
            if desired_state == 'running':
                client.ex_start_node(node)
                changed = True
            elif desired_state == 'stopped':
                client.ex_shutdown_graceful(node)
                changed = True
            if module.params['wait']:
                node = wait_for_server_state(client, module,
                                             server, desired_state)
            else:
                node = client.ex_get_node_by_id(server)
        node_list.append(node_to_node_obj(node))

    return (changed, node_list)


def core(module):
    credentials = get_credentials()
    if credentials is False:
        module.fail_json(msg="User credentials not found")
    user_id = credentials['user_id']
    key = credentials['key']
    region = 'dd-%s' % module.params['region']
    verify_ssl_cert = module.params['verify_ssl_cert']

    # Instantiate driver
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert
    DimensionData = get_driver(Provider.DIMENSIONDATA)
    client = DimensionData(user_id, key, region=region)
    state = module.params['state']
    if state == 'stopped' or state == 'running':
        return stoporstart_servers(client, module, state)
    elif state == 'present':
        return create_node(client, module)
    else:
        module.fail_json(msg='Unhandled state transition')


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(default='present', choices=['present',
                                                   'absent',
                                                   'running',
                                                   'stopped']),
            server_ids=dict(type='list', aliases=['server_id']),
            name=dict(),
            image=dict(),
            image_id=dict(),
            vlan=dict(),
            vlan_id=dict(),
            network_id=dict(),
            network=dict(),
            network_domain_id=dict(),
            network_domain=dict(),
            admin_password=dict(),
            description=dict(),
            memory_gb=dict(),
            unique_names=dict(type='bool', default='no'),
            region=dict(default='na', choices=dd_regions),
            verify_ssl_cert=dict(required=False, default=True, type='bool'),
            wait=dict(required=False, default=False, type='bool'),
            wait_time=dict(required=False, default=600, type='int'),
            wait_poll_interval=dict(required=False, default=2, type='int')
        )
    )
    if not HAS_LIBCLOUD:
        module.fail_json(msg='libcloud >= 1.0.0pre required for this module')

    try:
        (changed, data) = core(module)
    except (Exception), e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=changed, instances=data)


if __name__ == '__main__':
        main()
