# encoding: UTF-8
control "V-58023" do
  desc  "rationale", ""
  desc  "check", "
    Only a user with Full Admin and Security Admin roles can alter or
reconfigure the security safeguards.
    As the Full Admin, get a list of all RBAC users with the following command:
    $ couchbase-cli user-manage -c  <localhost>:<port>  -u <Full Admin> -p
<Password> --list
    If any users have the \"admin\" role or \"security_admin\" role that should
not, this is a finding.
  "
  desc  "fix", "
    Remove users who should not have Full Admin or Security Admin role. To
manage the roles this can be done by running the following command (Note: Do
not include the \"admin\" or the \"security_admin\" role in command):
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
     -p <Password> --set --rbac-username <user> --rbac-password <password> \\
     --rbac-name <name> --roles <roles> \\
     --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000340-DB-000304"
  tag "gid": "V-58023"
  tag "rid": "SV-72453r1_rule"
  tag "stig_id": "SRG-APP-000340-DB-000304"
  tag "fix_id": "F-63231r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]
end
