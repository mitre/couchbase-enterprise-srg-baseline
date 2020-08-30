# encoding: UTF-8
control "V-32192" do
  desc  "rationale", ""
  desc  "check", "
    If all accounts are authenticated by the organization-level
authentication/access mechanism and not by Couchbase, this is not a finding.
    If there are any accounts managed by Couchbase, review the system
documentation for justification and approval of these accounts.
    As the Full Admin, list all RBAC users in each cluster with the following
command:
      $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
<host>:<port> --list
    If any Couchbase-managed accounts exist that are not documented and
approved, this is a finding.
  "
  desc  "fix", "
    Integrate Couchbase security with an organization-level
authentication/access mechanism providing account management for all users,
groups, roles, and any other principals.
    For each Couchbase-managed account that is not documented and approved,
either transfer it to management by the external mechanism, or document the
need for it and obtain approval, as appropriate.
    To remove undocumented accounts, execute the following command:
      $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
<host>:<port> --set --delete --rbac-username <username> --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000023-DB-000001"
  tag "gid": "V-32192"
  tag "rid": "SV-42509r3_rule"
  tag "stig_id": "SRG-APP-000023-DB-000001"
  tag "fix_id": "F-36116r2_fix"
  tag "cci": ["CCI-000015"]
  tag "nist": ["AC-2 (1)", "Rev_4"]
end
