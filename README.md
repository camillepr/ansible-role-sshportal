Ansible SSHPortal Management Role
==================================

An Ansible role for installing and managing [SSHPortal](https://github.com/moul/sshportal) with declarative configuration. This role provides comprehensive management of SSHPortal's SQLite database, including users, groups, hosts, ACLs, and SSH keys.

**Tested on Ansible 11**

Features
--------

- **Complete SSHPortal Installation**: Automated deployment using Docker
- **Declarative Configuration**: Manage all SSHPortal resources through Ansible variables
- **Idempotent Operations**: Safe to run repeatedly without side effects
- **Automatic Cleanup**: Resources not in configuration are automatically removed
- **Protected System Resources**: Admin user and default groups are protected from modification
- **SSH Key Management**: Automatic generation and management of ed25519 SSH keys
- **Relationship Management**: Automatic assignment and removal of group memberships
- **Update Detection**: Tracks changes to ACLs, hosts, users, and associations

Requirements
------------

### Ansible Collections

This role requires the following Ansible collections:

```bash
ansible-galaxy collection install community.docker
ansible-galaxy collection install community.crypto
```

### System Requirements

- **Operating System**: Debian-based distributions (tested on Debian/Ubuntu)
- **Docker**: Must be installed and running
- **Python 3**: Required for management scripts
- **pip**: Python package manager for installing dependencies

### Python Dependencies

The following Python packages are automatically installed by the role:
- `cryptography`: For SSH key generation and management

Role Variables
--------------

### Required Variables

#### `sshportal_admin_invite_token`
The invite token for the admin user (first-time setup).

```yaml
sshportal_admin_invite_token: "your-secure-token-here"
```

### Optional Variables

#### `setup_sshportal` (default: `false`)
Whether to install and set up SSHPortal Docker container.

```yaml
setup_sshportal: true
```

#### `sshportal_host_groups` (default: `[]`)
List of host groups to create. The `default` group is protected and should not be included.

```yaml
sshportal_host_groups:
  - front
  - back
  - admin
```

#### `sshportal_user_groups` (default: `[]`)
List of user groups to create. The `default` group is protected and should not be included.

```yaml
sshportal_user_groups:
  - devfront
  - devback
  - superadmin
```

#### `sshportal_acls` (default: `[]`)
Access Control Lists defining which user groups can access which host groups.

```yaml
sshportal_acls:
  - name: allow_devfront_front
    user_group: devfront
    host_group: front
    action: allow
  - name: allow_superadmin_all
    user_group: superadmin
    host_group: admin
    action: allow
```

**Note**: The default ACL (default→default) is protected and should not be managed through this variable.

#### `sshportal_host_keys` (default: `[]`)
SSH keys to be generated and managed for hosts. Protected keys (`host`, `default`) should not be included.

```yaml
sshportal_host_keys:
  - production
  - staging
  - development
```

Keys are automatically generated as ed25519 key pairs. Public keys are displayed at the end of the playbook run.

#### `sshportal_hosts` (default: `[]`)
List of hosts (SSH targets) to be managed.

```yaml
sshportal_hosts:
  - name: webserver01
    url: ssh://user@10.0.1.10
    key: production
    groups:
      - front
      - admin
  - name: dbserver01
    url: ssh://dbuser@10.0.1.20
    key: production
    groups:
      - back
```

Each host must have:
- `name`: Unique identifier
- `url`: SSH connection string
- `key`: SSH key name (must exist in `sshportal_host_keys`)
- `groups`: List of host groups (optional)

#### `sshportal_users` (default: `[]`)
List of users to be created. The `admin` user is protected and should not be included.

```yaml
sshportal_users:
  - name: john.doe
    email: john.doe@example.com
    token: secure-invite-token-123
    groups:
      - devfront
      - superadmin
    ssh_pub_keys:
      - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdEfG..."
  
  - name: jane.smith
    email: jane.smith@example.com
    # Token is optional - will be NULL if omitted
    groups:
      - devback
```

Each user can have:
- `name`: Unique username (required)
- `email`: Email address (required)
- `token`: Invite token (optional - will be NULL if empty or omitted)
- `groups`: List of user groups (optional)
- `ssh_pub_keys`: List of SSH public keys (optional)

Default Role Behavior
---------------------

### Protected Resources

The following resources are protected from modification or deletion:

- **Admin User**: The `admin` user cannot be deleted or have its group memberships modified
- **Default Groups**: The `default` host group and user group cannot be deleted
- **Default ACL**: The ACL linking default user group to default host group cannot be modified
- **System Keys**: The `host` and `default` SSH keys cannot be deleted

### Automatic Cleanup

Resources that are no longer defined in your variables are automatically removed:

- **Groups**: Only if they have no members and are not used in ACLs
- **Hosts**: Automatically removed with all their group assignments
- **Users**: Removed with all SSH keys, group memberships, and related data
- **ACLs**: Removed with all group associations
- **SSH Keys**: Only if they are not in use by any host

### Change Detection

The role detects and reports changes to:

- ACL actions, host groups, or user groups
- Host URLs or SSH key assignments
- User emails or invite tokens
- All group membership assignments

Dependencies
------------

This role has no dependencies on other Ansible roles.

Example Playbook
----------------

### Basic Usage

```yaml
---
- hosts: sshportal_servers
  become: true
  roles:
    - role: ansible-sshportal
      vars:
        sshportal_admin_invite_token: "change-this-token"
        
        sshportal_host_groups:
          - production
          - staging
        
        sshportal_user_groups:
          - developers
          - admins
        
        sshportal_host_keys:
          - prod_key
          - staging_key
        
        sshportal_hosts:
          - name: prod-web-01
            url: ssh://ubuntu@192.168.1.10
            key: prod_key
            groups:
              - production
        
        sshportal_users:
          - name: developer1
            email: dev1@example.com
            token: dev-token-123
            groups:
              - developers
        
        sshportal_acls:
          - name: devs_to_staging
            user_group: developers
            host_group: staging
            action: allow
```

### Advanced Configuration

```yaml
---
- hosts: sshportal_servers
  become: true
  roles:
    - role: ansible-sshportal
      vars:
        sshportal_admin_invite_token: "{{ vault_sshportal_admin_token }}"
        
        sshportal_host_groups:
          - frontend
          - backend
          - database
          - monitoring
        
        sshportal_user_groups:
          - frontend_devs
          - backend_devs
          - dba_team
          - ops_team
        
        sshportal_host_keys:
          - prod_frontend
          - prod_backend
          - prod_database
        
        sshportal_hosts:
          - name: web-01
            url: ssh://deploy@web-01.prod.local
            key: prod_frontend
            groups:
              - frontend
          
          - name: api-01
            url: ssh://deploy@api-01.prod.local
            key: prod_backend
            groups:
              - backend
          
          - name: postgres-01
            url: ssh://postgres@db-01.prod.local
            key: prod_database
            groups:
              - database
        
        sshportal_users:
          - name: alice
            email: alice@company.com
            token: "{{ vault_alice_token }}"
            groups:
              - frontend_devs
              - ops_team
            ssh_pub_keys:
              - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbc123..."
          
          - name: bob
            email: bob@company.com
            groups:
              - backend_devs
              - ops_team
          
          - name: charlie
            email: charlie@company.com
            token: "{{ vault_charlie_token }}"
            groups:
              - dba_team
        
        sshportal_acls:
          - name: frontend_devs_to_frontend
            user_group: frontend_devs
            host_group: frontend
            action: allow
          
          - name: backend_devs_to_backend
            user_group: backend_devs
            host_group: backend
            action: allow
          
          - name: dba_to_database
            user_group: dba_team
            host_group: database
            action: allow
          
          - name: ops_full_access
            user_group: ops_team
            host_group: monitoring
            action: allow
```

### Minimal Installation Only

```yaml
---
- hosts: sshportal_servers
  become: true
  roles:
    - role: ansible-sshportal
      vars:
        setup_sshportal: true
        sshportal_admin_invite_token: "initial-setup-token"
```

File Structure
--------------

```
ansible-sshportal/
├── README.md
├── defaults/
│   └── main.yml          # Default variables
├── handlers/
│   └── main.yml          # Service handlers
├── meta/
│   └── main.yml          # Role metadata
├── tasks/
│   ├── main.yml          # Main task orchestration
│   └── setup-Debian.yml  # SSHPortal Docker installation
├── templates/
│   └── sshportalmgmt.py  # Python management script
├── tests/
│   ├── inventory         # Test inventory
│   └── test.yml          # Test playbook
└── vars/
    └── main.yml          # Internal variables
```

How It Works
------------

1. **Installation Phase** (if `setup_sshportal: true`):
   - Installs Docker if not present
   - Creates Docker volumes for SSHPortal data
   - Deploys SSHPortal container
   - Waits for SSHPortal to be ready
   - Initializes admin user with invite token

2. **Management Phase**:
   - Installs Python management script
   - Manages host groups (add/remove)
   - Manages user groups (add/remove)
   - Generates and manages SSH keys
   - Manages hosts with URL and key assignments
   - Manages host-to-group assignments
   - Manages users with optional tokens
   - Manages user-to-group assignments
   - Manages ACLs with group associations
   - Manages user SSH public keys
   - Displays generated SSH host keys

3. **Idempotency**:
   - All operations are idempotent
   - Only makes changes when necessary
   - Reports accurate change status

Troubleshooting
---------------

### Issue: "Protected groups cannot be managed"

**Cause**: You've included `default` in your host groups or user groups list.

**Solution**: Remove `default` from your group lists. It's automatically created by SSHPortal.

### Issue: "Protected user 'admin' cannot be managed"

**Cause**: You've included `admin` in your users list.

**Solution**: The admin user is created during installation. Don't include it in `sshportal_users`.

### Issue: "SSH key does not exist for host"

**Cause**: You've specified a key name for a host that isn't in `sshportal_host_keys`.

**Solution**: Add the key to `sshportal_host_keys` or use an existing key name.

### Issue: "User group has members, skipping deletion"

**Cause**: You've removed a group but users are still assigned to it.

**Solution**: Remove users from the group first, or remove the users entirely.

### Issue: Changes not being detected

**Cause**: The management script may not be detecting your updates.

**Solution**: Verify your variable syntax and check the playbook output for detailed change reports.

Viewing Generated Keys
---------------------

Generated SSH public keys are displayed at the end of each playbook run. You can also manually list them:

```bash
/usr/bin/python3 /usr/local/bin/sshportalmgmt.py listkeys
```

License
-------

MIT

Author Information
------------------

This role was created to provide declarative, automated management of SSHPortal installations using Ansible.

For issues, questions, or contributions, please refer to the role's repository.
