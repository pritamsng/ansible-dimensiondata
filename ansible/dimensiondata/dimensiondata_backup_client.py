#!/usr/bin/python
DOCUMENTATION = '''
---
module: dimensiondata_backup
short_description: add/delete backup client for a host
description:
    - Add or delete a backup client for a host in the Dimension Data Cloud
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
  region:
    description:
      - The target region.
    choices: ['na', 'eu', 'au', 'af', 'ap', 'latam', 'canada', 'canberra', 'id', 'in', 'il', 'sa']
    default: na
  client_type:
    description:
      - The service plan for backups.
    choices: [FA.Linux, PostgreSQL, MySQL]
  verify_ssl_cert:
    description:
      - Check that SSL certificate is valid.
    required: false
    default: true
  wait:
    description:
      - Should we wait for the task to complete before moving onto the next
    required: false
    default: false
  wait_time:
    description:
      - Only applicable if wait is true.  This is the amount of time in seconds to wait
    required: false
    default: 120

author:
    - "Jeff Dunham (@jadunham1)"
'''

EXAMPLES = '''
# Note: These examples don't include authorization.  You can set these by exporting DIDATA_USER and DIDATA_PASSWORD environment variables like:
# export DIDATA_USER=<username>
# export DIDATA_PASSWORD=<password>

# Basic enable backups example

- dimensiondata_backup:
    server_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'

# Basic remove backups example
- dimensiondata_backup:
    server_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: absent

# Full options enable
- dimensiondata_backup:
    server_ids:
      - '7ee719e9-7ae9-480b-9f16-c6b5de03463c'
    state: present
    wait: yes
    wait_time: 500
    service_plan: Advanced
    verify_Sssl_cert: no
'''

RETURN = '''
servers:
    description: list of servers this worked on
    returned: Always
    type: list
    contains: server_ids processed
'''

from ansible.module_utils.basic import *
from ansible.module_utils.dimensiondatacloud import *
try:
    from libcloud.common.dimensiondata import DimensionDataAPIException
    from libcloud.backup.drivers.dimensiondata import DimensionDataBackupDriver
    import libcloud.security
    HAS_LIBCLOUD = True
except:
    HAS_LIBCLOUD = False


def get_backup_client(details, client_type):
    if len(details.clients) > 0:
        for client in details.clients:
            if client.type.type == client_type:
                return client
    return None


def _backup_client_to_obj(backup_client):
    backup_client_dict = {}
    backup_client_dict['id'] = backup_client.id
    backup_client_dict['client_type'] = backup_client.type.type
    backup_client_dict['storage_policy'] = backup_client.storage_policy
    backup_client_dict['schedule_policy'] = backup_client.schedule_policy
    backup_client_dict['download_url'] = backup_client.download_url
    return backup_client_dict


def get_backup_details_for_host(client, server_id):
    try:
        backup_details = client.ex_get_backup_details_for_target(server_id)
    except DimensionDataAPIException as e:
        if e.msg.endswith('has not been provisioned for backup'):
            module.fail_json(msg="Server %s does not have backup enabled"
                             % server_id)
        else:
            module.fail_json(msg="Problem finding backup info for host: %s"
                             % e.msg)
    return backup_details


def handle_backup_client(module, client):
    changed = False
    state = module.params['state']
    client_type = module.params['client_type']
    server_clients_return = {}

    for server_id in module.params['server_ids']:
        backup_details = get_backup_details_for_host(client, server_id)
        backup_client = get_backup_client(backup_details, client_type)
        if state == 'absent' and backup_client is None:
            continue
        elif state == 'absent' and backup_client is not None:
            changed = True
            remove_client_from_server(client, module, server_id, backup_client)
        elif state == 'present' and backup_client is None:
            changed = True
            add_client_to_server(client, module, server_id)
            backup_details = get_backup_details_for_host(client, server_id)
            backup_client = get_backup_client(backup_details, client_type)
            server_clients_return[server_id] = \
                _backup_client_to_obj(backup_client)
        elif state == 'present' and backup_client is not None:
            server_clients_return[server_id] = \
                _backup_client_to_obj(backup_client)
        else:
            module.fail_json(msg="Unhandle state")

    module.exit_json(changed=changed, msg='Success',
                     backups=server_clients_return)


def remove_client_from_server(client, module, server_id, backup_client):
    try:
        client.ex_remove_client_from_target(server_id, backup_client)
    except DimensionDataAPIException as e:
        module.fail_json(msg="Failed removing client from host: %s" % e.msg)


def add_client_to_server(client, module, server_id):
    def getkeyordie(k):
        v = module.params[k]
        if v is None:
            module.fail_json(msg='Need key %s for adding a client' % k)
        return v

    storage_policy = getkeyordie('storage_policy')
    schedule_policy = getkeyordie('schedule_policy')
    client_type = getkeyordie('client_type')
    trigger = module.params['notify_trigger']
    notify_email = module.params['notify_email']

    try:
        backup_client = client.ex_add_client_to_target(
            server_id, client_type, storage_policy,
            schedule_policy, trigger, notify_email
        )
    except DimensionDataAPIException as e:
        module.fail_json(msg="Failed adding client to host: %s" % e.msg)
    return backup_client


def modify_backup_for_server(client, module, server_id, service_plan):
    extra = {'servicePlan': service_plan}
    client.update_target(server_id, extra=extra)


def _storage_policy_choices():
    storage_policy_lengths = ['14 Day', '30 Day', '60 Day', '90 Day',
                              '180 Day', '1 Year', '2 Year', '3 Year',
                              '4 Year', '5 Year', '6 Year', '7 Year']
    storage_policy_choices = []
    for storage_policy_length in storage_policy_lengths:
        storage_policy_choices.append(
            "%s Storage Policy" % storage_policy_length
        )
        storage_policy_choices.append(
            "%s Storage Policy + Secondary Copy" % storage_policy_length
        )
    return storage_policy_choices


def main():
    module = AnsibleModule(
        argument_spec=dict(
            region=dict(default='na', choices=['na', 'eu', 'au', 'af', 'ap',
                                               'latam', 'canada', 'canberra',
                                               'id', 'in', 'il', 'sa']),
            state=dict(default='present', choices=['present', 'absent']),
            server_ids=dict(required=True, type='list',
                            aliases=['server_id']),
            client_type=dict(required=True,
                             choices=['FA.Linux', 'MySQL', 'PostgreSQL']),
            schedule_policy=dict(choices=['12AM - 6AM', '6AM - 12PM',
                                          '12PM - 6PM', '6PM - 12AM']),
            storage_policy=dict(choices=_storage_policy_choices()),
            notify_email=dict(required=False, default='nobody@example.com'),
            notify_trigger=dict(required=False, default='ON_FAILURE',
                                choices=['ON_FAILURE', 'ON_SUCCESS']),
            verify_ssl_cert=dict(required=False, default=True, type='bool'),
            wait=dict(required=False, default=False, type='bool'),
            wait_time=dict(required=False, default=120, type='int')
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
    verify_ssl_cert = module.params['verify_ssl_cert']
    # Instantiate driver
    libcloud.security.VERIFY_SSL_CERT = verify_ssl_cert
    client = DimensionDataBackupDriver(user_id, key, region=region)

    handle_backup_client(module, client)

if __name__ == '__main__':
        main()
