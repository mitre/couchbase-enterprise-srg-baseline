# encoding: UTF-8

control "V-58129" do
  title "The role(s)/group(s) used to modify database structure (including but
not necessarily limited to tables, indexes, storage, etc.) and logic modules
(stored procedures, functions, triggers, links to software external to
Couchbase, etc.) must be restricted to authorized users."
  desc  "If Couchbase were to allow any user to make changes to database
structure or logic, then those changes might be implemented without undergoing
the appropriate testing and approvals that are part of a robust change
management process.

    Accordingly, only qualified and authorized individuals shall be allowed to
obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.

    Unmanaged changes that occur to the database software libraries or
configuration can lead to unauthorized or compromised installations.
  "
  desc  "rationale", ""
  desc  "check", "
    Identify the group(s)/role(s) established for Couchbase modification.
    Obtain the list of users in those group(s)/roles:
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
--list
    Identify the individuals authorized to modify Couchbase.
    If unauthorized access to the group(s)/role(s) has been granted, this is a
finding.
  "
  desc  "fix", "
    Revoke unauthorized memberships in Couchbase modification group(s)/role(s):
      $ cbq -u <Full Admin> -p <Password> -engine=http://<host>:<port>/
--script=\"REVOKE <role> FROM <username>\"
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000362"
  tag "gid": "V-58129"
  tag "rid": "SV-72559r1_rule"
  tag "stig_id": "SRG-APP-000133-DB-000362"
  tag "fix_id": "F-63337r1_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
end
