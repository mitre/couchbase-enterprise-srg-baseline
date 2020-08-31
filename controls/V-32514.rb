# encoding: UTF-8
control "V-32514" do
  desc  "rationale", ""
  desc  "check", "
    Check Couchbase settings and vendor documentation to verify that
administrative functionality is separate from user functionality.
    As the Full Admin, list current users and roles using the following example
command:
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
--list
    If any non-administrative account has the roles \"admin\" and
\"cluster_admin\", this is a finding.
    If administrator and general user functionality are not separated either
physically or logically, this is a finding.
  "
  desc  "fix", "
    Configure Couchbase to separate database administration and general user
functionality.
    As the Full Admin, remove unauthorized roles from a user with the following
command:
      $ cbq -u <Full Admin> -p <Password> -engine=http://<host>:<port>/
--script=\"REVOKE <role> FROM <username>\"
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000211-DB-000122"
  tag "gid": "V-32514"
  tag "rid": "SV-42851r3_rule"
  tag "stig_id": "SRG-APP-000211-DB-000122"
  tag "fix_id": "F-36429r2_fix"
  tag "cci": ["CCI-001082"]
  tag "nist": ["SC-2", "Rev_4"]
end
