# encoding: UTF-8
control "V-32415" do
  desc  "rationale", ""
  desc  "check", "
    Only a user with Full Admin role can change database configuration.
    As the Full Admin, get a list of all RBAC users with the following command:
    $ couchbase-cli user-manage -c  <localhost>:<port>  -u <Full Admin> -p
<Password> --list
    If any users have the \"admin\" role that should not, this is a finding.
    Couchbase configuration files directory -
     $ ls -la /opt/couchbase/etc/couchbase
    If the owner and group are not both \"couchbase\" for the configuration
files, this is a finding.
    If the file permissions are more permissive than \"600\", this is a finding.
  "
  desc  "fix", "
    Remove users who should not have Full Admin role. To manage the roles this
can be done by running the following command (Note: Do not include the
\"admin\" role in command):
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
     -p <Password> --set --rbac-username <user> --rbac-password <password> \\
     --rbac-name <name> --roles <roles> \\
     --auth-domain <domain>
    As the root or sudo user, change the permission of the following
directories:
    Couchbase configuration files directory:
      $ chown -R couchbase:couchbase /opt/couchbase/etc/couchbase
      $ chmod 600 /opt/couchbase/etc/couchbase/*
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000179"
  tag "gid": "V-32415"
  tag "rid": "SV-42752r3_rule"
  tag "stig_id": "SRG-APP-000133-DB-000179"
  tag "fix_id": "F-36330r2_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
end
