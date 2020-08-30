# encoding: UTF-8
control "V-32442" do
  desc  "rationale", ""
  desc  "check", "
    Review Couchbase settings to determine whether organizational users are
uniquely identified and authenticated when logging on/connecting to the system.
    As the Full Admin, list current users and roles using the following example
command:
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
--list
    If organizational users are not uniquely identified and authenticated, this
is a finding.

  "
  desc  "fix", "
    Configure Couchbase settings to uniquely identify and authenticate all
organizational users who log on/connect to the system.
    To remove undocumented accounts, execute the following command:
      $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
<host>:<port> --set --delete --rbac-username <username> --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000148-DB-000103"
  tag "gid": "V-32442"
  tag "rid": "SV-42779r4_rule"
  tag "stig_id": "SRG-APP-000148-DB-000103"
  tag "fix_id": "F-36357r2_fix"
  tag "cci": ["CCI-000764"]
  tag "nist": ["IA-2", "Rev_4"]
end
