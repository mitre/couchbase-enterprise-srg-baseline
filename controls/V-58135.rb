# encoding: UTF-8
control "V-58135" do
  desc  "rationale", ""
  desc  "check", "
    If Couchbase supports only software development, experimentation and/or
developer-level testing (that is, excluding production systems, integration
testing, stress testing, and user acceptance testing), this is not a finding.
    Review Couchbase and database security settings with respect to
non-administrative users ability to create, alter, or replace logic modules,
to include but not necessarily only stored procedures, functions, triggers, and
views.
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
--list
    If any such permissions exist and are not documented and approved, this is
a finding.
  "
  desc  "fix", "
    Document and obtain approval for any non-administrative users who require
the ability to create, alter or replace logic modules.
    Implement the approved permissions. Revoke any unapproved permissions.
    To remove undocumented accounts, execute the following command:
      $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
<host>:<port> --set --delete --rbac-username <username> --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000378-DB-000365"
  tag "gid": "V-58135"
  tag "rid": "SV-72565r1_rule"
  tag "stig_id": "SRG-APP-000378-DB-000365"
  tag "fix_id": "F-63343r1_fix"
  tag "cci": ["CCI-001812"]
  tag "nist": ["CM-11 (2)", "Rev_4"]
end
