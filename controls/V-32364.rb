# encoding: UTF-8

control "V-32364" do
  title "Couchbase must be able to generate audit records when
privileges/permissions are retrieved."
  desc  "Under some circumstances, it may be useful to monitor who/what is
reading privilege/permission/role information. Therefore, it must be possible
to configure auditing to do this. Couchbases typically make such information
available through views or functions.

    This requirement addresses explicit requests for privilege/permission/role
membership information. It does not refer to the implicit retrieval of
privileges/permissions/role memberships that Couchbase continually performs to
determine if any and every action on the database is permitted.
  "
  desc  "check", "
    Review Couchbase documentation to verify that audit records can be produced
when privileges/permissions/role memberships are retrieved.
    If Couchbase is not capable of this, this is a finding.
    If Couchbase is currently required to audit the retrieval of
privilege/permission/role membership information, review the Couchbase/database
security and audit configurations to verify that audit records are produced
when privileges/permissions/role memberships are retrieved.
    If they are not produced, this is a finding.
  "
  desc  "fix", "
    Deploy a Couchbase database capable of producing the required audit records
when privileges/permissions/role memberships are retrieved.
    If currently required, configure Couchbase to produce audit records when
privileges/permissions/role memberships are retrieved.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000091-DB-000066"
  tag "gid": "V-32364"
  tag "rid": "SV-42701r3_rule"
  tag "stig_id": "SRG-APP-000091-DB-000066"
  tag "fix_id": "F-36279r2_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
end
