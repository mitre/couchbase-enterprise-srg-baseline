# encoding: UTF-8
control "V-32203" do
  desc  "rationale", ""
  desc  "check", "
    From the system security plan or equivalent documentation, determine the
appropriate permissions on database objects for each kind (role) of user. If
this documentation is missing, this is a finding.
    Check Couchbase settings to determine whether users are restricted from
accessing objects and data they are not authorized to access.
    As the Full Admin, list all RBAC users in each cluster with the following
command:
      $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
<host>:<port> --list
    Verify the roles for each user account. If any user account is assigned a
role the exceed those documented, this is a finding.
  "
  desc  "fix", "
    Configure Couchbase settings and access controls to permit user access only
to objects and data that the user is authorized to view or interact with, and
to prevent access to all other objects and data.
    To update roles assigned to users, execute the following command:
      $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
<host>:<port> --set --delete --rbac-username <username> --roles <roles_list>
--auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000033-DB-000084"
  tag "gid": "V-32203"
  tag "rid": "SV-42520r3_rule"
  tag "stig_id": "SRG-APP-000033-DB-000084"
  tag "fix_id": "F-36127r3_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
end
