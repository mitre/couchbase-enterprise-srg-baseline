# encoding: UTF-8
control "V-32364" do
  desc  "rationale", ""
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
