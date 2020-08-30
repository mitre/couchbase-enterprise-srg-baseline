# encoding: UTF-8
control "V-32399" do
  desc  "rationale", ""
  desc  "check", "
    Only a user with Full Admin role can change auditing controls.
    As the Full Admin, get a list of all RBAC users with the following command:
    $ couchbase-cli user-manage -c  <localhost>:<port>  -u <Full Admin> -p
<Password> --list
    If any users have the \"admin\" role that should not, this is a finding.
    Additionally, the permissions of the config file should also be verified.
This can be done by running the following command:
     $ ls -la /opt/couchbase/etc/couchbase/static_config
    Review the ownership and permissions. If anyone other than couchbase is the
owner and group owner, this is a finding. If permissions are not set to 600,
this is a finding.
  "
  desc  "fix", "
    Remove users who should not have Full Admin role. To manage the roles this
can be done by running the following command (Note: Do not include the
\"admin\" role in command):
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
     -p <Password> --set --rbac-username <user> --rbac-password <password> \\
     --rbac-name <name> --roles <roles> \\
     --auth-domain <domain>
    As the root or sudo user, assign the correct permissions to the config file
fun the following commands:
      $ sudo chown -R couchbase:couchbase
/opt/couchbase/etc/couchbase/static_config
      $ sudo chmod 600 /opt/couchbase/etc/couchbase/static_config
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000123-DB-000204"
  tag "gid": "V-32399"
  tag "rid": "SV-42736r3_rule"
  tag "stig_id": "SRG-APP-000123-DB-000204"
  tag "fix_id": "F-36314r2_fix"
  tag "cci": ["CCI-001495"]
  tag "nist": ["AU-9", "Rev_4"]
end
