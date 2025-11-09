#!/usr/bin/python3
import datetime
from datetime import timezone
import sqlite3
import argparse
import sys
import base64
import struct
import socket
from contextlib import contextmanager
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import hashlib

# Global variable to store the Ansible controller hostname
ANSIBLE_CONTROLLER_HOST = None

# Global variable to store protected users list
PROTECTED_USERS = {'admin', 'sshportal'}  # Default protected users

def get_utc_now():
    """Get current UTC time with timezone information."""
    return datetime.datetime.now(timezone.utc)

def get_ansible_comment():
    """Generate a comment with the Ansible controller hostname."""
    if ANSIBLE_CONTROLLER_HOST:
        return f"ansible from {ANSIBLE_CONTROLLER_HOST}"
    else:
        # Fallback to local hostname if not set
        hostname = socket.gethostname()
        return f"ansible from {hostname}"

def parse_openssh_pubkey_to_wire_format(pubkey_string):
    """
    Convert an OpenSSH public key string to SSH wire format (binary blob).
    
    Args:
        pubkey_string: SSH public key in OpenSSH format (e.g., "ssh-ed25519 AAAAC3...")
    
    Returns:
        bytes: SSH wire format as used in the 'key' blob field
    """
    try:
        # Split the key string
        parts = pubkey_string.strip().split()
        if len(parts) < 2:
            raise ValueError("Invalid SSH public key format")
        
        # Get the base64-encoded key data (second part)
        key_data_b64 = parts[1]
        
        # Decode from base64 to get the wire format
        wire_format = base64.b64decode(key_data_b64)
        
        return wire_format
    except Exception as e:
        print(f"Error parsing SSH public key: {e}")
        return None

@contextmanager
def get_db_connection(path):
    """
    Context manager for database connections.
    Automatically handles connection and cursor lifecycle.
    
    Usage:
        with get_db_connection(path) as (conn, cursor):
            cursor.execute("SELECT * FROM table")
            conn.commit()
    """
    conn = None
    try:
        conn = sqlite3.connect(path,
                              detect_types=sqlite3.PARSE_DECLTYPES |
                                          sqlite3.PARSE_COLNAMES)
        cursor = conn.cursor()
        print("Connected to SQLite")
        yield conn, cursor
    except sqlite3.Error as error:
        print(f"Error while working with SQLite: {error}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            cursor.close()
            conn.close()

def switch(action, argsobj):
    if action == "addacl":
        addAcl(argsobj['dbpath'], argsobj['hostgroup'], argsobj['usergroup'], argsobj['action'], argsobj['comment'])
    elif action == "manageacls":
        manageAcls(argsobj['dbpath'], argsobj['acls'])
    elif action == "addhostgroup":
        addHostGroup(argsobj['dbpath'], argsobj['name'])
    elif action == "managehostgroups":
        manageHostGroups(argsobj['dbpath'], argsobj['groups'])
    elif action == "addusergroup":
        addUserGroup(argsobj['dbpath'], argsobj['name'])
    elif action == "manageusergroups":
        manageUserGroups(argsobj['dbpath'], argsobj['groups'])
    elif action == "addkey":
        addKey(argsobj['dbpath'], argsobj['name'])
    elif action == "managekeys":
        manageKeys(argsobj['dbpath'], argsobj['keys'])
    elif action == "listkeys":
        listKeys(argsobj['dbpath'])
    elif action == "addhost":
        addHost(argsobj['dbpath'], argsobj['name'], argsobj['url'])
    elif action == "managehosts":
        manageHosts(argsobj['dbpath'], argsobj['hosts'])
    elif action == "assignhostgroup":
        assignHostGroup(argsobj['dbpath'], argsobj['host'], argsobj['group'])
    elif action == "managehostgroupassignments":
        manageHostGroupAssignments(argsobj['dbpath'], argsobj['assignments'])
    elif action == "assignusergroup":
        assignUserGroup(argsobj['dbpath'], argsobj['user'], argsobj['group'])
    elif action == "manageusergroupassignments":
        manageUserGroupAssignments(argsobj['dbpath'], argsobj['assignments'])
    elif action == "inviteuser":
        inviteUser(argsobj['dbpath'], argsobj['name'], argsobj['email'], argsobj['token'])
    elif action == "manageusers":
        manageUsers(argsobj['dbpath'], argsobj['users'])
    elif action == "manageuserkeys":
        manageUserKeys(argsobj['dbpath'], argsobj['user'], argsobj['keys'])

def addAcl(path, hostgroup, usergroup, action, comment):
    try:
        with get_db_connection(path) as (conn, cursor):
            # Check if ACL with this comment already exists
            res = cursor.execute("SELECT id FROM acls WHERE comment = ?", (comment,))
            existing_acl = res.fetchone()
            
            if existing_acl:
                print("ACL already exists, not doing anything")
                return
            
            # Get host group ID
            res_hostgroup = cursor.execute("SELECT id FROM host_groups WHERE name = ?", (hostgroup,))
            hostgroup_id = res_hostgroup.fetchone()
            
            if not hostgroup_id:
                print(f"Error: Host group '{hostgroup}' does not exist")
                return
            
            # Get user group ID
            res_usergroup = cursor.execute("SELECT id FROM user_groups WHERE name = ?", (usergroup,))
            usergroup_id = res_usergroup.fetchone()
            
            if not usergroup_id:
                print(f"Error: User group '{usergroup}' does not exist")
                return
            
            print(f'Adding ACL: {comment}')
            
            # Insert ACL
            sqlite_insert_acl = """INSERT INTO 'acls'
                              ('created_at', 'updated_at', 'action', 'weight', 'comment') 
                              VALUES (?, ?, ?, ?, ?);"""
            
            data_tuple = (get_utc_now(), get_utc_now(), action, 0, get_ansible_comment())
            cursor.execute(sqlite_insert_acl, data_tuple)
            
            # Get the newly created ACL ID
            acl_id = cursor.lastrowid
            
            # Link ACL to host group
            sqlite_insert_host_group_acl = """INSERT INTO 'host_group_acls'
                              ('acl_id', 'host_group_id') 
                              VALUES (?, ?);"""
            cursor.execute(sqlite_insert_host_group_acl, (acl_id, hostgroup_id[0]))
            
            # Link ACL to user group
            sqlite_insert_user_group_acl = """INSERT INTO 'user_group_acls'
                              ('acl_id', 'user_group_id') 
                              VALUES (?, ?);"""
            cursor.execute(sqlite_insert_user_group_acl, (acl_id, usergroup_id[0]))
            
            conn.commit()
            print("ACL added successfully\n")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def manageAcls(path, acls_data):
    """
    Manage ACLs. Adds new ACLs and removes ACLs that are not in the provided list.
    Protected ACL with user_group='default' AND host_group='default' cannot be deleted or added via this function.
    acls_data format: "name1:::hostgroup1:::usergroup1:::action1|||name2:::hostgroup2:::usergroup2:::action2|||..."
    """
    try:
        with get_db_connection(path) as (conn, cursor):
            # Parse the acls_data (|||separated string into list of ACL dicts)
            acls = []
            if acls_data:
                acl_entries = [a.strip() for a in acls_data.split('|||') if a.strip()]
                for entry in acl_entries:
                    parts = entry.split(':::', 3)
                    if len(parts) == 4:
                        acls.append({
                            'name': parts[0].strip(),
                            'host_group': parts[1].strip(),
                            'user_group': parts[2].strip(),
                            'action': parts[3].strip()
                        })
            
            # Check for protected ACL (default->default) in the input list
            protected_acls_found = [a['name'] for a in acls if a['user_group'].lower() == 'default' and a['host_group'].lower() == 'default']
            if protected_acls_found:
                print(f"Error: Protected ACL (user_group='default' + host_group='default') cannot be managed: {', '.join(protected_acls_found)}")
                print(f"The default->default ACL is a system ACL and should not be in sshportal_acls list")
                sys.exit(1)
            
            # Get existing ACLs with their relationships
            res_existing = cursor.execute("""
                SELECT a.id, a.comment, a.action,
                       hg.name as host_group_name,
                       ug.name as user_group_name
                FROM acls a
                LEFT JOIN host_group_acls hga ON a.id = hga.acl_id
                LEFT JOIN host_groups hg ON hga.host_group_id = hg.id
                LEFT JOIN user_group_acls uga ON a.id = uga.acl_id
                LEFT JOIN user_groups ug ON uga.user_group_id = ug.id
            """)
            existing_acls = {}
            for row in res_existing.fetchall():
                acl_id, comment, action, host_group_name, user_group_name = row
                existing_acls[comment] = {
                    'id': acl_id,
                    'action': action,
                    'host_group': host_group_name,
                    'user_group': user_group_name
                }
            
            acls_added = 0
            acls_updated = 0
            acls_removed = 0
            acls_unchanged = 0
            acls_protected = 0
            
            # Add or update ACLs
            for acl in acls:
                name = acl['name']
                host_group = acl['host_group']
                user_group = acl['user_group']
                action = acl['action']
                
                # Get host group ID
                res_hostgroup = cursor.execute("SELECT id FROM host_groups WHERE name = ?", (host_group,))
                hostgroup_id = res_hostgroup.fetchone()
                
                if not hostgroup_id:
                    print(f"Error: Host group '{host_group}' does not exist for ACL '{name}'")
                    continue
                
                # Get user group ID
                res_usergroup = cursor.execute("SELECT id FROM user_groups WHERE name = ?", (user_group,))
                usergroup_id = res_usergroup.fetchone()
                
                if not usergroup_id:
                    print(f"Error: User group '{user_group}' does not exist for ACL '{name}'")
                    continue
                
                if name not in existing_acls:
                    print(f"Adding ACL: {name}")
                    
                    # Insert ACL
                    sqlite_insert_acl = """INSERT INTO 'acls'
                                      ('created_at', 'updated_at', 'action', 'weight', 'comment') 
                                      VALUES (?, ?, ?, ?, ?);"""
                    
                    data_tuple = (get_utc_now(), get_utc_now(), action, 0, get_ansible_comment())
                    cursor.execute(sqlite_insert_acl, data_tuple)
                    
                    # Get the newly created ACL ID
                    acl_id = cursor.lastrowid
                    
                    # Link ACL to host group
                    sqlite_insert_host_group_acl = """INSERT INTO 'host_group_acls'
                                      ('acl_id', 'host_group_id') 
                                      VALUES (?, ?);"""
                    cursor.execute(sqlite_insert_host_group_acl, (acl_id, hostgroup_id[0]))
                    
                    # Link ACL to user group
                    sqlite_insert_user_group_acl = """INSERT INTO 'user_group_acls'
                                      ('acl_id', 'user_group_id') 
                                      VALUES (?, ?);"""
                    cursor.execute(sqlite_insert_user_group_acl, (acl_id, usergroup_id[0]))
                    
                    acls_added += 1
                else:
                    # Check if action, host_group, or user_group changed
                    existing = existing_acls[name]
                    needs_update = False
                    
                    if existing['action'] != action:
                        needs_update = True
                    
                    if existing['host_group'] != host_group or existing['user_group'] != user_group:
                        needs_update = True
                    
                    if needs_update:
                        print(f"Updating ACL: {name}")
                        acl_id = existing['id']
                        
                        # Update the action field and comment
                        sqlite_update = """UPDATE 'acls' 
                                         SET 'updated_at' = ?, 'action' = ?, 'comment' = ?
                                         WHERE id = ?;"""
                        cursor.execute(sqlite_update, (get_utc_now(), action, get_ansible_comment(), acl_id))
                        
                        # Update host group association if changed
                        if existing['host_group'] != host_group:
                            # Delete old association
                            cursor.execute("DELETE FROM host_group_acls WHERE acl_id = ?", (acl_id,))
                            # Add new association
                            cursor.execute("INSERT INTO host_group_acls (acl_id, host_group_id) VALUES (?, ?)",
                                         (acl_id, hostgroup_id[0]))
                        
                        # Update user group association if changed
                        if existing['user_group'] != user_group:
                            # Delete old association
                            cursor.execute("DELETE FROM user_group_acls WHERE acl_id = ?", (acl_id,))
                            # Add new association
                            cursor.execute("INSERT INTO user_group_acls (acl_id, user_group_id) VALUES (?, ?)",
                                         (acl_id, usergroup_id[0]))
                        
                        acls_updated += 1
                    else:
                        acls_unchanged += 1
            
            # Get current ACL names from input
            input_acl_names = {a['name'] for a in acls}
            
            # Remove ACLs that are not in the new list
            for existing_acl_name, acl_data in existing_acls.items():
                if existing_acl_name not in input_acl_names:
                    acl_id = acl_data['id']
                    
                    # Check if it's the protected ACL (default->default)
                    # Get the groups associated with this ACL
                    res_acl_groups = cursor.execute("""
                        SELECT hg.name, ug.name
                        FROM acls a
                        LEFT JOIN host_group_acls hga ON a.id = hga.acl_id
                        LEFT JOIN host_groups hg ON hga.host_group_id = hg.id
                        LEFT JOIN user_group_acls uga ON a.id = uga.acl_id
                        LEFT JOIN user_groups ug ON uga.user_group_id = ug.id
                        WHERE a.id = ?
                    """, (acl_id,))
                    
                    groups = res_acl_groups.fetchone()
                    if groups:
                        host_group_name, user_group_name = groups
                        if host_group_name and user_group_name:
                            if host_group_name.lower() == 'default' and user_group_name.lower() == 'default':
                                print(f"Skipping protected ACL (default->default): {existing_acl_name}")
                                acls_protected += 1
                                continue
                    
                    print(f"Removing ACL: {existing_acl_name}")
                    
                    # Delete related data first (foreign key constraints)
                    cursor.execute("DELETE FROM host_group_acls WHERE acl_id = ?", (acl_id,))
                    cursor.execute("DELETE FROM user_group_acls WHERE acl_id = ?", (acl_id,))
                    
                    # Delete the ACL
                    cursor.execute("DELETE FROM acls WHERE id = ?", (acl_id,))
                    acls_removed += 1
            
            conn.commit()
            
            print(f"ACL management summary:")
            print(f"  - Added: {acls_added}")
            print(f"  - Updated: {acls_updated}")
            print(f"  - Removed: {acls_removed}")
            print(f"  - Unchanged: {acls_unchanged}")
            if acls_protected > 0:
                print(f"  - Protected (not deleted): {acls_protected}")
            
            # Return status for ansible changed detection
            if acls_added > 0 or acls_updated > 0 or acls_removed > 0:
                print("ACLs changed")
            else:
                print("ACLs not doing anything")
    except sqlite3.Error:
        pass  # Error already logged by context manager
        
def addHostGroup(path, group):
    """Add a host group if it doesn't already exist."""
    try:
        with get_db_connection(path) as (conn, cursor):
            res = cursor.execute("SELECT name FROM host_groups WHERE name = ?", (group,))
            if len(res.fetchall()) > 0:
                print("Group already exists, not doing anything")
            else:
                print('Adding '+ group)
                sqlite_insert_with_param = """INSERT INTO 'host_groups'
                                  ('created_at', 'updated_at', 'name', 'comment') 
                                  VALUES (?, ?, ?, ?);"""

                data_tuple = (get_utc_now(), get_utc_now(), group, get_ansible_comment())
                cursor.execute(sqlite_insert_with_param, data_tuple)
                conn.commit()
                print("Host added successfully \n")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def manageHostGroups(path, groups_list):
    """
    Manage host groups. Adds new groups and removes groups that are not in the provided list.
    Protected group 'default' cannot be deleted or added via this function.
    Groups with hosts or ACLs cannot be deleted.
    """
    # Define protected groups that should never be deleted or managed
    PROTECTED_GROUPS = {'default'}
    
    try:
        with get_db_connection(path) as (conn, cursor):
            # Parse the groups_list (comma-separated string into list)
            if groups_list:
                groups = [g.strip() for g in groups_list.split(',') if g.strip()]
            else:
                groups = []
            
            # Check for protected groups in the input list
            protected_groups_found = [g for g in groups if g.lower() in PROTECTED_GROUPS]
            if protected_groups_found:
                print(f"Error: Protected groups cannot be managed via this command: {', '.join(protected_groups_found)}")
                print(f"Protected group 'default' is a system group and should not be in sshportal_host_groups list")
                sys.exit(1)
            
            # Get existing groups
            res_existing = cursor.execute("SELECT id, name FROM host_groups")
            existing_groups = {row[1]: row[0] for row in res_existing.fetchall()}
            
            groups_added = 0
            groups_removed = 0
            groups_unchanged = 0
            groups_protected = 0
            groups_in_use = 0
            
            # Add new groups
            for group in groups:
                if group not in existing_groups:
                    print(f'Adding host group: {group}')
                    # Insert group
                    sqlite_insert_with_param = """INSERT INTO 'host_groups'
                                      ('created_at', 'updated_at', 'name', 'comment') 
                                      VALUES (?, ?, ?, ?);"""
                    
                    data_tuple = (get_utc_now(), get_utc_now(), group, get_ansible_comment())
                    cursor.execute(sqlite_insert_with_param, data_tuple)
                    groups_added += 1
                else:
                    groups_unchanged += 1
            
            # Remove groups that are not in the new list
            for existing_group, group_id in existing_groups.items():
                if existing_group not in groups:
                    # Check if it's a protected group
                    if existing_group.lower() in PROTECTED_GROUPS:
                        print(f"Skipping protected host group: {existing_group}")
                        groups_protected += 1
                        continue
                    
                    # Check if group has hosts assigned
                    res_hosts = cursor.execute("SELECT COUNT(*) FROM host_host_groups WHERE host_group_id = ?", (group_id,))
                    host_count = res_hosts.fetchone()[0]
                    
                    if host_count > 0:
                        print(f"Warning: Host group '{existing_group}' has {host_count} host(s) assigned, skipping deletion")
                        groups_in_use += 1
                        continue
                    
                    # Check if group is used in ACLs
                    res_acls = cursor.execute("SELECT COUNT(*) FROM host_group_acls WHERE host_group_id = ?", (group_id,))
                    acl_count = res_acls.fetchone()[0]
                    
                    if acl_count > 0:
                        print(f"Warning: Host group '{existing_group}' is used in {acl_count} ACL(s), skipping deletion")
                        groups_in_use += 1
                        continue
                    
                    print(f"Removing host group: {existing_group}")
                    cursor.execute("DELETE FROM host_groups WHERE id = ?", (group_id,))
                    groups_removed += 1
            
            conn.commit()
            
            print(f"Host group management summary:")
            print(f"  - Added: {groups_added}")
            print(f"  - Removed: {groups_removed}")
            print(f"  - Unchanged: {groups_unchanged}")
            if groups_protected > 0:
                print(f"  - Protected (not deleted): {groups_protected}")
            if groups_in_use > 0:
                print(f"  - In use (not deleted): {groups_in_use}")
            
            # Return status for ansible changed detection
            if groups_added > 0 or groups_removed > 0:
                print("Host groups changed")
            else:
                print("Host groups not doing anything")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def addUserGroup(path, group):
    """Add a user group if it doesn't already exist."""
    try:
        with get_db_connection(path) as (conn, cursor):
            res = cursor.execute("SELECT name FROM user_groups WHERE name = ?", (group,))
            if len(res.fetchall()) > 0:
                print("Group already exists, not doing anything")
            else:
                print('Adding '+ group)
                sqlite_insert_with_param = """INSERT INTO 'user_groups'
                                  ('created_at', 'updated_at', 'name', 'comment') 
                                  VALUES (?, ?, ?, ?);"""

                data_tuple = (get_utc_now(), get_utc_now(), group, get_ansible_comment())
                cursor.execute(sqlite_insert_with_param, data_tuple)
                conn.commit()
                print("Host added successfully \n")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def manageUserGroups(path, groups_list):
    """
    Manage user groups. Adds new groups and removes groups that are not in the provided list.
    Protected group 'default' cannot be deleted or added via this function.
    Groups with members cannot be deleted.
    """
    # Define protected groups that should never be deleted or managed
    PROTECTED_GROUPS = {'default'}
    
    try:
        with get_db_connection(path) as (conn, cursor):
            # Parse the groups_list (comma-separated string into list)
            if groups_list:
                groups = [g.strip() for g in groups_list.split(',') if g.strip()]
            else:
                groups = []
            
            # Check for protected groups in the input list
            protected_groups_found = [g for g in groups if g.lower() in PROTECTED_GROUPS]
            if protected_groups_found:
                print(f"Error: Protected groups cannot be managed via this command: {', '.join(protected_groups_found)}")
                print(f"Protected group 'default' is a system group and should not be in sshportal_user_groups list")
                sys.exit(1)
            
            # Get existing groups
            res_existing = cursor.execute("SELECT id, name FROM user_groups")
            existing_groups = {row[1]: row[0] for row in res_existing.fetchall()}
            
            groups_added = 0
            groups_removed = 0
            groups_unchanged = 0
            groups_protected = 0
            groups_in_use = 0
            
            # Add new groups
            for group in groups:
                if group not in existing_groups:
                    print(f'Adding user group: {group}')
                    # Insert group
                    sqlite_insert_with_param = """INSERT INTO 'user_groups'
                                      ('created_at', 'updated_at', 'name', 'comment') 
                                      VALUES (?, ?, ?, ?);"""
                    
                    data_tuple = (get_utc_now(), get_utc_now(), group, get_ansible_comment())
                    cursor.execute(sqlite_insert_with_param, data_tuple)
                    groups_added += 1
                else:
                    groups_unchanged += 1
            
            # Remove groups that are not in the new list
            for existing_group, group_id in existing_groups.items():
                if existing_group not in groups:
                    # Check if it's a protected group
                    if existing_group.lower() in PROTECTED_GROUPS:
                        print(f"Skipping protected user group: {existing_group}")
                        groups_protected += 1
                        continue
                    
                    # Check if group has members
                    res_members = cursor.execute("SELECT COUNT(*) FROM user_user_groups WHERE user_group_id = ?", (group_id,))
                    member_count = res_members.fetchone()[0]
                    
                    if member_count > 0:
                        print(f"Warning: User group '{existing_group}' has {member_count} member(s), skipping deletion")
                        groups_in_use += 1
                        continue
                    
                    # Check if group is used in ACLs
                    res_acls = cursor.execute("SELECT COUNT(*) FROM user_group_acls WHERE user_group_id = ?", (group_id,))
                    acl_count = res_acls.fetchone()[0]
                    
                    if acl_count > 0:
                        print(f"Warning: User group '{existing_group}' is used in {acl_count} ACL(s), skipping deletion")
                        groups_in_use += 1
                        continue
                    
                    print(f"Removing user group: {existing_group}")
                    cursor.execute("DELETE FROM user_groups WHERE id = ?", (group_id,))
                    groups_removed += 1
            
            conn.commit()
            
            print(f"User group management summary:")
            print(f"  - Added: {groups_added}")
            print(f"  - Removed: {groups_removed}")
            print(f"  - Unchanged: {groups_unchanged}")
            if groups_protected > 0:
                print(f"  - Protected (not deleted): {groups_protected}")
            if groups_in_use > 0:
                print(f"  - In use (not deleted): {groups_in_use}")
            
            # Return status for ansible changed detection
            if groups_added > 0 or groups_removed > 0:
                print("User groups changed")
            else:
                print("User groups not doing anything")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def addHost(path, host, url):
    """Add a host if it doesn't already exist."""
    try:
        with get_db_connection(path) as (conn, cursor):
            res = cursor.execute("SELECT name FROM hosts WHERE name = ?", (host,))
            if len(res.fetchall()) > 0:
                print("Host already exists, not doing anything")
            else:
                print('Adding '+ host)
                sqlite_insert_with_param = """INSERT INTO 'hosts'
                                  ('created_at', 'updated_at', 'name', 'url', 'comment') 
                                  VALUES (?, ?, ?, ?, ?);"""

                data_tuple = (get_utc_now(), get_utc_now(), host, url, get_ansible_comment())
                cursor.execute(sqlite_insert_with_param, data_tuple)
                conn.commit()
                print("Host added successfully \n")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def manageHosts(path, hosts_data):
    """
    Manage hosts. Adds new hosts and removes hosts that are not in the provided list.
    hosts_data format: "name1:::url1:::key1:::logging1:::hop1|||name2:::url2:::key2:::logging2:::hop2|||..."
    If logging is not specified, defaults to 'input'.
    If hop is not specified, defaults to None (NULL).
    """
    try:
        with get_db_connection(path) as (conn, cursor):
            # Parse the hosts_data (|||separated string into list of host dicts)
            hosts = []
            if hosts_data:
                host_entries = [h.strip() for h in hosts_data.split('|||') if h.strip()]
                for entry in host_entries:
                    parts = entry.split(':::', 4)
                    if len(parts) >= 2:
                        hosts.append({
                            'name': parts[0].strip(),
                            'url': parts[1].strip(),
                            'key': parts[2].strip() if len(parts) >= 3 and parts[2].strip() else None,
                            'logging': parts[3].strip() if len(parts) >= 4 and parts[3].strip() else 'input',
                            'hop': parts[4].strip() if len(parts) >= 5 and parts[4].strip() else None
                        })
            
            # Get existing hosts with their SSH key names, logging settings, and hop
            res_existing = cursor.execute("""
                SELECT h.id, h.name, h.url, sk.name as key_name, h.logging, hop.name as hop_name
                FROM hosts h
                LEFT JOIN ssh_keys sk ON h.ssh_key_id = sk.id
                LEFT JOIN hosts hop ON h.hop_id = hop.id
            """)
            existing_hosts = {}
            for row in res_existing.fetchall():
                host_id, host_name, url, key_name, logging, hop_name = row
                existing_hosts[host_name] = {
                    'id': host_id,
                    'url': url,
                    'key': key_name,
                    'logging': logging,
                    'hop': hop_name
                }
            
            hosts_added = 0
            hosts_updated = 0
            hosts_removed = 0
            hosts_unchanged = 0
            
            # Add or update hosts
            for host in hosts:
                name = host['name']
                url = host['url']
                key = host['key']
                logging = host['logging']
                hop = host['hop']
                
                # Get SSH key ID if key is specified
                ssh_key_id = None
                if key:
                    res_key = cursor.execute("SELECT id FROM ssh_keys WHERE name = ?", (key,))
                    key_row = res_key.fetchone()
                    if key_row:
                        ssh_key_id = key_row[0]
                    else:
                        print(f"Warning: SSH key '{key}' does not exist for host '{name}'")
                
                # Get hop ID if hop is specified
                hop_id = None
                if hop:
                    res_hop = cursor.execute("SELECT id FROM hosts WHERE name = ?", (hop,))
                    hop_row = res_hop.fetchone()
                    if hop_row:
                        hop_id = hop_row[0]
                    else:
                        print(f"Warning: Hop host '{hop}' does not exist for host '{name}'")
                
                if name not in existing_hosts:
                    print(f"Adding host: {name}")
                    # Insert host detail
                    sqlite_insert_with_param = """INSERT INTO 'hosts'
                                      ('created_at', 'updated_at', 'name', 'url', 'ssh_key_id', 'logging', 'hop_id', 'comment') 
                                      VALUES (?, ?, ?, ?, ?, ?, ?, ?);"""
                    
                    data_tuple = (get_utc_now(), get_utc_now(), name, url, ssh_key_id, logging, hop_id, get_ansible_comment())
                    cursor.execute(sqlite_insert_with_param, data_tuple)
                    hosts_added += 1
                else:
                    # Check if URL, key, logging, or hop changed
                    existing = existing_hosts[name]
                    needs_update = False
                    
                    if existing['url'] != url or existing['key'] != key or existing['logging'] != logging or existing['hop'] != hop:
                        needs_update = True
                    
                    if needs_update:
                        print(f"Updating host: {name}")
                        sqlite_update = """UPDATE 'hosts' 
                                         SET 'updated_at' = ?, 'url' = ?, 'ssh_key_id' = ?, 'logging' = ?, 'hop_id' = ?, 'comment' = ?
                                         WHERE name = ?;"""
                        cursor.execute(sqlite_update, (get_utc_now(), url, ssh_key_id, logging, hop_id, get_ansible_comment(), name))
                        hosts_updated += 1
                    else:
                        hosts_unchanged += 1
            
            # Get current host names from input
            input_host_names = {h['name'] for h in hosts}
            
            # Remove hosts that are not in the new list
            for existing_host_name, host_data in existing_hosts.items():
                if existing_host_name not in input_host_names:
                    print(f"Removing host: {existing_host_name}")
                    host_id = host_data['id']
                    
                    # Delete related data first (foreign key constraints)
                    cursor.execute("DELETE FROM host_host_groups WHERE host_id = ?", (host_id,))
                    cursor.execute("DELETE FROM sessions WHERE host_id = ?", (host_id,))
                    
                    # Delete the host
                    cursor.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
                    hosts_removed += 1
            
            conn.commit()
            
            print(f"Host management summary:")
            print(f"  - Added: {hosts_added}")
            print(f"  - Updated: {hosts_updated}")
            print(f"  - Removed: {hosts_removed}")
            print(f"  - Unchanged: {hosts_unchanged}")
            
            # Return status for ansible changed detection
            if hosts_added > 0 or hosts_updated > 0 or hosts_removed > 0:
                print("Hosts changed")
            else:
                print("Hosts not doing anything")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def addKey(path, key):
    """Generate an ed25519 key pair and add it to the database."""
    try:
        with get_db_connection(path) as (conn, cursor):
            res = cursor.execute("SELECT name FROM ssh_keys WHERE name = ?", (key,))
            if len(res.fetchall()) > 0:
                print("Key already exists, not doing anything")
                return
            
            print(f'Generating ed25519 key pair for: {key}')
            
            # Generate ed25519 key pair
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            
            # Serialize private key in OpenSSH format
            priv_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key in OpenSSH format
            pub_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            )
            
            # Calculate fingerprint (MD5 hash of the public key)
            pub_key_raw = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            fingerprint = hashlib.md5(pub_key_raw).hexdigest()
            fingerprint_formatted = ':'.join([fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)])
            
            # Insert key detail
            sqlite_insert_with_param = """INSERT INTO 'ssh_keys'
                              ('created_at', 'updated_at', 'name', 'type', 'length', 'fingerprint', 'priv_key', 'pub_key', 'comment') 
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"""
            
            data_tuple = (
                get_utc_now(), 
                get_utc_now(), 
                key,
                'ed25519',
                256,
                fingerprint_formatted,
                priv_key_bytes.decode('utf-8'),
                pub_key_bytes.decode('utf-8'),
                get_ansible_comment()
            )
            cursor.execute(sqlite_insert_with_param, data_tuple)
            conn.commit()
            print(f"Key '{key}' added successfully")
            print(f"Public key: {pub_key_bytes.decode('utf-8')}")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def manageKeys(path, keys_list):
    """
    Manage SSH keys. Adds new keys and removes keys that are not in the provided list.
    Protected keys 'host' and 'default' cannot be deleted or added via this function.
    """
    # Define protected keys that should never be deleted or managed
    PROTECTED_KEYS = {'host', 'default'}
    
    try:
        with get_db_connection(path) as (conn, cursor):
            # Parse the keys_list (comma-separated string into list)
            if keys_list:
                keys = [k.strip() for k in keys_list.split(',') if k.strip()]
            else:
                keys = []
            
            # Check for protected keys in the input list
            protected_keys_found = [k for k in keys if k.lower() in PROTECTED_KEYS]
            if protected_keys_found:
                print(f"Error: Protected keys cannot be managed via this command: {', '.join(protected_keys_found)}")
                print(f"Protected keys ('host', 'default') are system keys and should not be in sshportal_host_keys list")
                sys.exit(1)
            
            # Get existing keys
            res_existing = cursor.execute("SELECT id, name FROM ssh_keys")
            existing_keys = {row[1]: row[0] for row in res_existing.fetchall()}
            
            keys_added = 0
            keys_removed = 0
            keys_unchanged = 0
            keys_protected = 0
            
            # Add new keys
            for key in keys:
                if key not in existing_keys:
                    print(f'Generating ed25519 key pair for: {key}')
                    
                    # Generate ed25519 key pair
                    private_key = ed25519.Ed25519PrivateKey.generate()
                    public_key = private_key.public_key()
                    
                    # Serialize private key in OpenSSH format
                    priv_key_bytes = private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.OpenSSH,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                    
                    # Serialize public key in OpenSSH format
                    pub_key_bytes = public_key.public_bytes(
                        encoding=serialization.Encoding.OpenSSH,
                        format=serialization.PublicFormat.OpenSSH
                    )
                    
                    # Calculate fingerprint (MD5 hash of the public key)
                    pub_key_raw = public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                    fingerprint = hashlib.md5(pub_key_raw).hexdigest()
                    fingerprint_formatted = ':'.join([fingerprint[i:i+2] for i in range(0, len(fingerprint), 2)])
                    
                    # Insert key
                    sqlite_insert_key = """INSERT INTO 'ssh_keys'
                                      ('created_at', 'updated_at', 'name', 'type', 'length', 'fingerprint', 'priv_key', 'pub_key', 'comment') 
                                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"""
                    
                    data_tuple = (
                        get_utc_now(), 
                        get_utc_now(), 
                        key,
                        'ed25519',
                        256,
                        fingerprint_formatted,
                        priv_key_bytes.decode('utf-8'),
                        pub_key_bytes.decode('utf-8'),
                        get_ansible_comment()
                    )
                    cursor.execute(sqlite_insert_key, data_tuple)
                    keys_added += 1
                    print(f"Key '{key}' added successfully")
                else:
                    keys_unchanged += 1
            
            # Remove keys that are not in the new list
            for existing_key, key_id in existing_keys.items():
                if existing_key not in keys:
                    # Check if it's a protected key
                    if existing_key.lower() in PROTECTED_KEYS:
                        print(f"Skipping protected key: {existing_key}")
                        keys_protected += 1
                        continue
                        
                    print(f"Removing key: {existing_key}")
                    # Check if key is in use by any host
                    res_in_use = cursor.execute("SELECT COUNT(*) FROM hosts WHERE ssh_key_id = ?", (key_id,))
                    count = res_in_use.fetchone()[0]
                    if count > 0:
                        print(f"Warning: Key '{existing_key}' is in use by {count} host(s), skipping deletion")
                        keys_unchanged += 1
                    else:
                        cursor.execute("DELETE FROM ssh_keys WHERE id = ?", (key_id,))
                        keys_removed += 1
            
            conn.commit()
            
            print(f"Key management summary:")
            print(f"  - Added: {keys_added}")
            print(f"  - Removed: {keys_removed}")
            print(f"  - Unchanged: {keys_unchanged}")
            if keys_protected > 0:
                print(f"  - Protected (not deleted): {keys_protected}")
            
            # Return status for ansible changed detection
            if keys_added > 0 or keys_removed > 0:
                print("Keys changed")
            else:
                print("Keys not doing anything")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def listKeys(path):
    """List all SSH keys with their public keys."""
    try:
        with get_db_connection(path) as (conn, cursor):
            res = cursor.execute("SELECT name, type, pub_key, fingerprint FROM ssh_keys ORDER BY name")
            keys = res.fetchall()
            
            if not keys:
                print("No keys found in database")
            else:
                print("\n=== SSH Keys Public Keys ===")
                for key in keys:
                    name, key_type, pub_key, fingerprint = key
                    print(f"\nKey Name: {name}")
                    print(f"Type: {key_type}")
                    print(f"Fingerprint: {fingerprint}")
                    print(f"Public Key: {pub_key}")
                    print("-" * 80)
    except sqlite3.Error:
        pass  # Error already logged by context manager

def assignHostGroup(path, host, group):
    try:
        with get_db_connection(path) as (conn, cursor):
            res_host_id = cursor.execute("SELECT id from hosts WHERE name = ?", (host,))
            host_id = res_host_id.fetchone()
            res_group_id = cursor.execute("SELECT id from host_groups WHERE name = ?", (group,))
            group_id = res_group_id.fetchone()

            if not host_id or not group_id:
                print("Host or group not found")
                return

            print('Assigning group')
            for h in host_id:
                for g in group_id:
                    res_check = cursor.execute("SELECT host_group_id FROM host_host_groups WHERE host_group_id = ? and host_id = ?", (g, h))
                    if len(res_check.fetchall()) > 0:
                        print("Host already in group, not doing anything")
                    else:
                        # insert host detail
                        sqlite_insert_with_param = """INSERT INTO 'host_host_groups'
                                          ('host_group_id', 'host_id') 
                                          VALUES (?, ?);"""
                
                        data_tuple = (g, h)
                        cursor.execute(sqlite_insert_with_param, data_tuple)
                        conn.commit()
                        print("Group assigned successfully \n")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def manageHostGroupAssignments(path, assignments_data):
    """
    Manage host group assignments. Adds new assignments and removes assignments that are not in the provided list.
    assignments_data format: "host1:::group1|||host1:::group2|||host2:::group1|||..."
    """
    try:
        with get_db_connection(path) as (conn, cursor):
            # Parse the assignments_data
            desired_assignments = []
            if assignments_data:
                assignment_entries = [a.strip() for a in assignments_data.split('|||') if a.strip()]
                for entry in assignment_entries:
                    parts = entry.split(':::', 1)
                    if len(parts) == 2:
                        desired_assignments.append({
                            'host': parts[0].strip(),
                            'group': parts[1].strip()
                        })
            
            # Get all existing host-group assignments
            res_existing = cursor.execute("""
                SELECT h.id, h.name, hg.id, hg.name
                FROM host_host_groups hhg
                JOIN hosts h ON hhg.host_id = h.id
                JOIN host_groups hg ON hhg.host_group_id = hg.id
            """)
            existing_assignments = {}
            for row in res_existing.fetchall():
                host_id, host_name, group_id, group_name = row
                key = f"{host_name}:::{group_name}"
                existing_assignments[key] = {'host_id': host_id, 'group_id': group_id}
            
            assignments_added = 0
            assignments_removed = 0
            assignments_unchanged = 0
            
            # Add new assignments
            for assignment in desired_assignments:
                host_name = assignment['host']
                group_name = assignment['group']
                key = f"{host_name}:::{group_name}"
                
                if key not in existing_assignments:
                    # Get host ID
                    res_host = cursor.execute("SELECT id FROM hosts WHERE name = ?", (host_name,))
                    host_row = res_host.fetchone()
                    
                    if not host_row:
                        print(f"Warning: Host '{host_name}' does not exist, skipping assignment to '{group_name}'")
                        continue
                    
                    # Get group ID
                    res_group = cursor.execute("SELECT id FROM host_groups WHERE name = ?", (group_name,))
                    group_row = res_group.fetchone()
                    
                    if not group_row:
                        print(f"Warning: Host group '{group_name}' does not exist, skipping assignment for '{host_name}'")
                        continue
                    
                    print(f"Assigning host '{host_name}' to group '{group_name}'")
                    sqlite_insert = """INSERT INTO 'host_host_groups'
                                      ('host_group_id', 'host_id') 
                                      VALUES (?, ?);"""
                    cursor.execute(sqlite_insert, (group_row[0], host_row[0]))
                    
                    # Update the host's updated_at timestamp
                    cursor.execute("UPDATE hosts SET updated_at = ? WHERE id = ?", 
                                  (get_utc_now(), host_row[0]))
                    
                    assignments_added += 1
                else:
                    assignments_unchanged += 1
            
            # Get desired assignment keys
            desired_keys = {f"{a['host']}:::{a['group']}" for a in desired_assignments}
            
            # Remove assignments that are not in the desired list
            for existing_key, assignment_data in existing_assignments.items():
                if existing_key not in desired_keys:
                    host_id = assignment_data['host_id']
                    group_id = assignment_data['group_id']
                    host_name, group_name = existing_key.split(':::')
                    
                    print(f"Removing assignment: host '{host_name}' from group '{group_name}'")
                    cursor.execute("DELETE FROM host_host_groups WHERE host_id = ? AND host_group_id = ?", 
                                  (host_id, group_id))
                    
                    # Update the host's updated_at timestamp
                    cursor.execute("UPDATE hosts SET updated_at = ? WHERE id = ?", 
                                  (get_utc_now(), host_id))
                    
                    assignments_removed += 1
            
            conn.commit()
            
            print(f"Host group assignment summary:")
            print(f"  - Added: {assignments_added}")
            print(f"  - Removed: {assignments_removed}")
            print(f"  - Unchanged: {assignments_unchanged}")
            
            # Return status for ansible changed detection
            if assignments_added > 0 or assignments_removed > 0:
                print("Host group assignments changed")
            else:
                print("Host group assignments not doing anything")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def assignUserGroup(path, user, group):
    try:
        with get_db_connection(path) as (conn, cursor):
            res_user_id = cursor.execute("SELECT id from users WHERE name = ?", (user,))
            user_id = res_user_id.fetchone()
            res_group_id = cursor.execute("SELECT id from user_groups WHERE name = ?", (group,))
            group_id = res_group_id.fetchone()

            if not user_id or not group_id:
                print("User or group not found")
                return

            print('Assigning group')
            for u in user_id:
                for g in group_id:
                    res_check = cursor.execute("SELECT user_group_id FROM user_user_groups WHERE user_group_id = ? and user_id = ?", (g, u))
                    if len(res_check.fetchall()) > 0:
                        print("User already in group, not doing anything")
                    else:
                        # insert user detail
                        sqlite_insert_with_param = """INSERT INTO 'user_user_groups'
                                          ('user_group_id', 'user_id') 
                                          VALUES (?, ?);"""
                
                        data_tuple = (g, u)
                        cursor.execute(sqlite_insert_with_param, data_tuple)
                        conn.commit()
                        print("Group assigned successfully \n")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def manageUserGroupAssignments(path, assignments_data):
    """
    Manage user group assignments. Adds new assignments and removes assignments that are not in the provided list.
    assignments_data format: "user1:::group1|||user1:::group2|||user2:::group1|||..."
    """
    try:
        with get_db_connection(path) as (conn, cursor):
            # Parse the assignments_data
            desired_assignments = []
            if assignments_data:
                assignment_entries = [a.strip() for a in assignments_data.split('|||') if a.strip()]
                for entry in assignment_entries:
                    parts = entry.split(':::', 1)
                    if len(parts) == 2:
                        desired_assignments.append({
                            'user': parts[0].strip(),
                            'group': parts[1].strip()
                        })
            
            # Get all existing user-group assignments
            res_existing = cursor.execute("""
                SELECT u.id, u.name, ug.id, ug.name
                FROM user_user_groups uug
                JOIN users u ON uug.user_id = u.id
                JOIN user_groups ug ON uug.user_group_id = ug.id
            """)
            existing_assignments = {}
            for row in res_existing.fetchall():
                user_id, user_name, group_id, group_name = row
                key = f"{user_name}:::{group_name}"
                existing_assignments[key] = {'user_id': user_id, 'group_id': group_id}
            
            assignments_added = 0
            assignments_removed = 0
            assignments_unchanged = 0
            assignments_protected = 0
            
            # Add new assignments
            for assignment in desired_assignments:
                user_name = assignment['user']
                group_name = assignment['group']
                key = f"{user_name}:::{group_name}"
                
                # Protect users from group assignment changes
                if user_name.lower() in {u.lower() for u in PROTECTED_USERS}:
                    print(f"Skipping assignment for protected user '{user_name}' to group '{group_name}'")
                    assignments_protected += 1
                    continue
                
                if key not in existing_assignments:
                    # Get user ID
                    res_user = cursor.execute("SELECT id FROM users WHERE name = ?", (user_name,))
                    user_row = res_user.fetchone()
                    
                    if not user_row:
                        print(f"Warning: User '{user_name}' does not exist, skipping assignment to '{group_name}'")
                        continue
                    
                    # Get group ID
                    res_group = cursor.execute("SELECT id FROM user_groups WHERE name = ?", (group_name,))
                    group_row = res_group.fetchone()
                    
                    if not group_row:
                        print(f"Warning: User group '{group_name}' does not exist, skipping assignment for '{user_name}'")
                        continue
                    
                    print(f"Assigning user '{user_name}' to group '{group_name}'")
                    sqlite_insert = """INSERT INTO 'user_user_groups'
                                      ('user_group_id', 'user_id') 
                                      VALUES (?, ?);"""
                    cursor.execute(sqlite_insert, (group_row[0], user_row[0]))
                    
                    # Update the user's updated_at timestamp
                    cursor.execute("UPDATE users SET updated_at = ? WHERE id = ?", 
                                  (get_utc_now(), user_row[0]))
                    
                    assignments_added += 1
                else:
                    assignments_unchanged += 1
            
            # Get desired assignment keys
            desired_keys = {f"{a['user']}:::{a['group']}" for a in desired_assignments}
            
            # Remove assignments that are not in the desired list
            for existing_key, assignment_data in existing_assignments.items():
                if existing_key not in desired_keys:
                    user_id = assignment_data['user_id']
                    group_id = assignment_data['group_id']
                    user_name, group_name = existing_key.split(':::')
                    
                    # Protect users from group assignment removal
                    if user_name.lower() in {u.lower() for u in PROTECTED_USERS}:
                        print(f"Protecting '{user_name}' user assignment to group '{group_name}' from removal")
                        assignments_protected += 1
                        continue
                    
                    print(f"Removing assignment: user '{user_name}' from group '{group_name}'")
                    cursor.execute("DELETE FROM user_user_groups WHERE user_id = ? AND user_group_id = ?", 
                                  (user_id, group_id))
                    
                    # Update the user's updated_at timestamp
                    cursor.execute("UPDATE users SET updated_at = ? WHERE id = ?", 
                                  (get_utc_now(), user_id))
                    
                    assignments_removed += 1
            
            conn.commit()
            
            print(f"User group assignment summary:")
            print(f"  - Added: {assignments_added}")
            print(f"  - Removed: {assignments_removed}")
            print(f"  - Unchanged: {assignments_unchanged}")
            print(f"  - Protected: {assignments_protected}")
            
            # Return status for ansible changed detection
            if assignments_added > 0 or assignments_removed > 0:
                print("User group assignments changed")
            else:
                print("User group assignments not doing anything")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def inviteUser(path, name, email, token):
    """Add a user if it doesn't already exist."""
    try:
        with get_db_connection(path) as (conn, cursor):
            res = cursor.execute("SELECT name FROM users WHERE name = ?", (name,))
            if len(res.fetchall()) > 0:
                print("User already exists, not doing anything")
            else:
                print('Adding '+ name)
                sqlite_insert_with_param = """INSERT INTO 'users'
                                  ('created_at', 'updated_at', 'name', 'email', 'invite_token', 'comment') 
                                  VALUES (?, ?, ?, ?, ?, ?);"""

                data_tuple = (get_utc_now(), get_utc_now(), name, email, token, get_ansible_comment())
                cursor.execute(sqlite_insert_with_param, data_tuple)
                conn.commit()
                print("User added successfully \n")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def manageUsers(path, users_data):
    """
    Manage users. Adds new users and removes users that are not in the provided list.
    Protected users (from --protected-users parameter) cannot be deleted or added via this function.
    Token is optional - if empty or not provided, invite_token will be NULL.
    users_data format: "name1:::email1:::token1|||name2:::email2:::|||name3:::email3:::token3|||..."
    """
    # Use global protected users list
    
    try:
        with get_db_connection(path) as (conn, cursor):
            # Parse the users_data (comma-separated string into list of user dicts)
            users = []
            if users_data:
                user_entries = [u.strip() for u in users_data.split('|||') if u.strip()]
                for entry in user_entries:
                    parts = entry.split(':::', 2)
                    if len(parts) >= 2:
                        # Token is optional (third part)
                        token = parts[2].strip() if len(parts) == 3 and parts[2].strip() else None
                        users.append({
                            'name': parts[0].strip(),
                            'email': parts[1].strip(),
                            'token': token
                        })
            
            # Check for protected users in the input list
            protected_users_found = [u['name'] for u in users if u['name'].lower() in PROTECTED_USERS]
            if protected_users_found:
                print(f"Error: Protected users cannot be managed via this command: {', '.join(protected_users_found)}")
                print(f"Protected user 'admin' is a system user and should not be in sshportal_users list")
                sys.exit(1)
            
            # Get existing users
            res_existing = cursor.execute("SELECT id, name, email, invite_token FROM users")
            existing_users = {row[1]: {'id': row[0], 'email': row[2], 'token': row[3]} for row in res_existing.fetchall()}
            
            users_added = 0
            users_removed = 0
            users_unchanged = 0
            users_protected = 0
            
            # Add or update users
            for user in users:
                name = user['name']
                email = user['email']
                token = user['token']
                
                if name not in existing_users:
                    print(f"Adding user: {name}")
                    # Insert user detail
                    sqlite_insert_with_param = """INSERT INTO 'users'
                                      ('created_at', 'updated_at', 'name', 'email', 'invite_token', 'comment') 
                                      VALUES (?, ?, ?, ?, ?, ?);"""
                    
                    data_tuple = (get_utc_now(), get_utc_now(), name, email, token, get_ansible_comment())
                    cursor.execute(sqlite_insert_with_param, data_tuple)
                    users_added += 1
                else:
                    # Check if email or token changed
                    existing_token = existing_users[name]['token']
                    if existing_users[name]['email'] != email or existing_token != token:
                        print(f"Updating user: {name}")
                        sqlite_update = """UPDATE 'users' 
                                         SET 'updated_at' = ?, 'email' = ?, 'invite_token' = ?, 'comment' = ?
                                         WHERE name = ?;"""
                        cursor.execute(sqlite_update, (get_utc_now(), email, token, get_ansible_comment(), name))
                        users_added += 1  # Count updates as changes
                    else:
                        users_unchanged += 1
            
            # Get current user names from input
            input_user_names = {u['name'] for u in users}
            
            # Remove users that are not in the new list
            for existing_user_name, user_data in existing_users.items():
                if existing_user_name not in input_user_names:
                    # Check if it's a protected user
                    if existing_user_name.lower() in PROTECTED_USERS:
                        print(f"Skipping protected user: {existing_user_name}")
                        users_protected += 1
                        continue
                    
                    print(f"Removing user: {existing_user_name}")
                    user_id = user_data['id']
                    
                    # Delete related data first (foreign key constraints)
                    cursor.execute("DELETE FROM user_keys WHERE user_id = ?", (user_id,))
                    cursor.execute("DELETE FROM user_user_groups WHERE user_id = ?", (user_id,))
                    cursor.execute("DELETE FROM user_user_roles WHERE user_id = ?", (user_id,))
                    cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
                    cursor.execute("DELETE FROM events WHERE author_id = ?", (user_id,))
                    
                    # Delete the user
                    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                    users_removed += 1
            
            conn.commit()
            
            print(f"User management summary:")
            print(f"  - Added/Updated: {users_added}")
            print(f"  - Removed: {users_removed}")
            print(f"  - Unchanged: {users_unchanged}")
            if users_protected > 0:
                print(f"  - Protected (not deleted): {users_protected}")
            
            # Return status for ansible changed detection
            if users_added > 0 or users_removed > 0:
                print("Users changed")
            else:
                print("Users not doing anything")
    except sqlite3.Error:
        pass  # Error already logged by context manager

def manageUserKeys(path, user, keys_list):
    """
    Manage SSH public keys for a user. 
    Adds new keys and removes keys that are not in the provided list.
    Protected users (from --protected-users parameter) will be skipped.
    """
    # Use global protected users list
    
    try:
        with get_db_connection(path) as (conn, cursor):
            # Check if this is a protected user
            if user.lower() in PROTECTED_USERS:
                print(f"Skipping key management for protected user '{user}'")
                return
            
            # Get user ID
            res_user = cursor.execute("SELECT id FROM users WHERE name = ?", (user,))
            user_row = res_user.fetchone()
            
            if not user_row:
                print(f"Error: User '{user}' does not exist")
                return
            
            user_id = user_row[0]
            
            # Parse the keys_list (comma-separated string into list)
            if keys_list:
                keys = [k.strip() for k in keys_list.split(',') if k.strip()]
            else:
                keys = []
            
            # Get existing keys for the user
            res_existing = cursor.execute("SELECT id, authorized_key FROM user_keys WHERE user_id = ?", (user_id,))
            existing_keys = {row[1]: row[0] for row in res_existing.fetchall()}
            
            keys_added = 0
            keys_removed = 0
            keys_unchanged = 0
            
            # Add new keys
            for key in keys:
                # Ensure key has trailing newline (sshportal CLI adds this)
                key_with_newline = key if key.endswith('\n') else key + '\n'
                
                if key_with_newline not in existing_keys:
                    print(f"Adding key for user '{user}': {key[:50]}...")
                    
                    # Convert OpenSSH format to wire format blob
                    key_blob = parse_openssh_pubkey_to_wire_format(key)
                    
                    if key_blob is None:
                        print(f"Error: Failed to parse SSH key for user '{user}', skipping")
                        continue
                    
                    sqlite_insert_key = """INSERT INTO 'user_keys'
                                      ('created_at', 'updated_at', 'key', 'user_id', 'authorized_key', 'comment') 
                                      VALUES (?, ?, ?, ?, ?, ?);"""
                    
                    data_tuple = (get_utc_now(), get_utc_now(), key_blob, user_id, key_with_newline, get_ansible_comment())
                    cursor.execute(sqlite_insert_key, data_tuple)
                    keys_added += 1
                else:
                    keys_unchanged += 1
            
            # Remove keys that are not in the new list
            # Normalize input keys for comparison (add newline if missing)
            normalized_input_keys = {k if k.endswith('\n') else k + '\n' for k in keys}
            
            for existing_key, key_id in existing_keys.items():
                if existing_key not in normalized_input_keys:
                    print(f"Removing key for user '{user}': {existing_key[:50]}...")
                    cursor.execute("DELETE FROM user_keys WHERE id = ?", (key_id,))
                    keys_removed += 1
            
            # Update the user's updated_at timestamp if any changes were made
            if keys_added > 0 or keys_removed > 0:
                cursor.execute("UPDATE users SET updated_at = ? WHERE id = ?", 
                              (get_utc_now(), user_id))
            
            conn.commit()
            
            print(f"Key management summary for user '{user}':")
            print(f"  - Added: {keys_added}")
            print(f"  - Removed: {keys_removed}")
            print(f"  - Unchanged: {keys_unchanged}")
            
            # Return status for ansible changed detection
            if keys_added > 0 or keys_removed > 0:
                print("Keys changed")
            else:
                print("Keys not doing anything")
    except sqlite3.Error:
        pass  # Error already logged by context manager


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    
    # Add global optional argument for Ansible controller hostname
    parser.add_argument('--ansible-host', action='store', dest='ansible_host', help='Ansible controller hostname')
    
    # Add global optional argument for protected users list (comma-separated)
    parser.add_argument('--protected-users', action='store', dest='protected_users', help='Comma-separated list of protected users (default: admin,sshportal)')

    subparsers_obj = parser.add_subparsers(dest='subparsers_obj')
    
    functionnality_1_obj = subparsers_obj.add_parser('addhostgroup')
    functionnality_1_obj.add_argument('--name', action='store')
    functionnality_1_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')
    
    functionnality_2_obj = subparsers_obj.add_parser('addkey')
    functionnality_2_obj.add_argument('--name', action='store')
    functionnality_2_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_3_obj = subparsers_obj.add_parser('addhost')
    functionnality_3_obj.add_argument('--name', action='store')
    functionnality_3_obj.add_argument('--url', action='store')
    functionnality_3_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')
    
    functionnality_4_obj = subparsers_obj.add_parser('assignhostgroup')
    functionnality_4_obj.add_argument('--host', action='store')
    functionnality_4_obj.add_argument('--group', action='store')
    functionnality_4_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_5_obj = subparsers_obj.add_parser('inviteuser')
    functionnality_5_obj.add_argument('--name', action='store')
    functionnality_5_obj.add_argument('--email', action='store')
    functionnality_5_obj.add_argument('--token', action='store')
    functionnality_5_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_6_obj = subparsers_obj.add_parser('addusergroup')
    functionnality_6_obj.add_argument('--name', action='store')
    functionnality_6_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_7_obj = subparsers_obj.add_parser('assignusergroup')
    functionnality_7_obj.add_argument('--user', action='store')
    functionnality_7_obj.add_argument('--group', action='store')
    functionnality_7_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_8_obj = subparsers_obj.add_parser('addacl')
    functionnality_8_obj.add_argument('--hostgroup', action='store')
    functionnality_8_obj.add_argument('--usergroup', action='store')
    functionnality_8_obj.add_argument('--action', action='store')
    functionnality_8_obj.add_argument('--comment', action='store')
    functionnality_8_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_9_obj = subparsers_obj.add_parser('manageuserkeys')
    functionnality_9_obj.add_argument('--user', action='store')
    functionnality_9_obj.add_argument('--keys', action='store')
    functionnality_9_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_10_obj = subparsers_obj.add_parser('managekeys')
    functionnality_10_obj.add_argument('--keys', action='store')
    functionnality_10_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_11_obj = subparsers_obj.add_parser('listkeys')
    functionnality_11_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_12_obj = subparsers_obj.add_parser('manageusers')
    functionnality_12_obj.add_argument('--users', action='store')
    functionnality_12_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_13_obj = subparsers_obj.add_parser('manageusergroups')
    functionnality_13_obj.add_argument('--groups', action='store')
    functionnality_13_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_14_obj = subparsers_obj.add_parser('manageacls')
    functionnality_14_obj.add_argument('--acls', action='store')
    functionnality_14_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_15_obj = subparsers_obj.add_parser('managehosts')
    functionnality_15_obj.add_argument('--hosts', action='store')
    functionnality_15_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_16_obj = subparsers_obj.add_parser('managehostgroups')
    functionnality_16_obj.add_argument('--groups', action='store')
    functionnality_16_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_17_obj = subparsers_obj.add_parser('manageusergroupassignments')
    functionnality_17_obj.add_argument('--assignments', action='store')
    functionnality_17_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')

    functionnality_18_obj = subparsers_obj.add_parser('managehostgroupassignments')
    functionnality_18_obj.add_argument('--assignments', action='store')
    functionnality_18_obj.add_argument('--dbpath', action='store', default='/var/lib/docker/volumes/sshportal__var_lib_sshportal/_data/sshportal.db')


    args_obj = vars(parser.parse_args())
    
    # Set Ansible controller hostname if provided
    if args_obj.get('ansible_host'):
        ANSIBLE_CONTROLLER_HOST = args_obj['ansible_host']
    
    # Set protected users list if provided
    if args_obj.get('protected_users'):
        PROTECTED_USERS = {u.strip() for u in args_obj['protected_users'].split(',') if u.strip()}

    switch(args_obj['subparsers_obj'], args_obj)