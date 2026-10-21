Rule files for PII Shield. Only .yaml/.yml/.json/.txt/.lst/.csv files are synced; this README is ignored.

- rules.yaml: network, identity, cloud, secret, address and Israel rules. Its header gives the full schema.
- secrets.yaml: API tokens, Bearer/Basic credentials, URL and command-line credentials, session cookies.
- identity.yaml: Windows SIDs, LDAP names, cloud principals, user names in log lines and home paths.
- hosts.yaml: syslog host fields, host= pairs, Kerberos SPN hosts, default Windows and inventory names.
- json_fields.yaml: JSON and Python-dict values masked by key name (json_keys, json_key_contains).
- patterns.json: ticket IDs and on-premises mailboxes.

secrets.yaml, identity.yaml, hosts.yaml and json_fields.yaml adapt patterns from
socprime/logtotal-sanitizer (Apache-2.0). See NOTICE in the app repo.
