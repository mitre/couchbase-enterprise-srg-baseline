# encoding: UTF-8

control "V-32412" do
  title "Database objects (including but not limited to tables, indexes,
storage, stored procedures, functions, triggers, links to software external to
Couchbase, etc.) must be owned by database/Couchbase principals authorized for
ownership."
  desc  "Within the database, object ownership implies full privileges to the
owned object, including the privilege to assign access to the owned objects to
other subjects. Database functions and procedures can be coded using definer's
rights. This allows anyone who utilizes the object to perform the actions if
they were the owner. If not properly managed, this can lead to privileged
actions being taken by unauthorized individuals.

    Conversely, if critical tables or other objects rely on unauthorized owner
accounts, these objects may be lost when an account is removed.
  "
  desc  "rationale", ""
  desc  "check", "
    Review system documentation to identify accounts authorized to own database
objects. Review accounts that own objects in the database(s).
    As the Full Admin, list current users and roles using the following example
command:
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
--list
    If any database objects are found to be owned by users not authorized to
own database objects, this is a finding.
  "
  desc  "fix", "
    Assign ownership of authorized objects to authorized object owner accounts.
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
--edit -user-groups
    To remove undocumented accounts, execute the following command:
      $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
<host>:<port> --set --delete --rbac-username <username> --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000200"
  tag "gid": "V-32412"
  tag "rid": "SV-42749r3_rule"
  tag "stig_id": "SRG-APP-000133-DB-000200"
  tag "fix_id": "F-36327r3_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
end
