# encoding: UTF-8
control "V-32481" do
  desc  "rationale", ""
  desc  "check", "
    Review Couchbase settings to determine whether non-organizational users are
uniquely identified and authenticated when logging onto the system.
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
--list
    If non-organizational users are not uniquely identified and authenticated,
this is a finding.
  "
  desc  "fix", "
    Configure Couchbase settings to uniquely identify and authenticate all
non-organizational users who log onto the system.
    As the Full Admin, delete a user with the following command:
      $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
<host>:<port>  --delete --rbac-username <username> --auth-domain <domain>
    As the Full Admin, create a user with the following command:
      $ couchbase-cli user-manage  -u <Full Admin> -p <Password> --cluster
<host>:<port> --set --rbac-username <username> --rbac-password < user password>
--rbac-name <name> --roles <roles>  --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000180-DB-000115"
  tag "gid": "V-32481"
  tag "rid": "SV-42818r3_rule"
  tag "stig_id": "SRG-APP-000180-DB-000115"
  tag "fix_id": "F-36396r2_fix"
  tag "cci": ["CCI-000804"]
  tag "nist": ["IA-8", "Rev_4"]
end
