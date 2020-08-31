# encoding: UTF-8
control "V-58121" do
  desc  "rationale", ""
  desc  "check", "
    Review Couchbase documentation to verify that administrative users can
specify database objects for which access must be audited, and can specify
which kinds of access must be audited.
    If Couchbase is not capable of this, this is a finding.
    Review Couchbase documentation to determine whether the application owner
has specified database objects (tables, views, procedures, functions, etc.) for
which access must be audited.
    Review the Couchbase/database security and audit settings to verify that
audit records are created for unsuccessful attempts at the specified access to
the specified objects.
    If not, this is a finding.
  "
  desc  "fix", "
    Ensure couchbase is capable of producing the required audit records when
object access occurs.
    Configure audit settings to create audit records when the specified access
to the specified objects occurs.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000507-DB-000357"
  tag "gid": "V-58121"
  tag "rid": "SV-72551r1_rule"
  tag "stig_id": "SRG-APP-000507-DB-000357"
  tag "fix_id": "F-63329r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
end
