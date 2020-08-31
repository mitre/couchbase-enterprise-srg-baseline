# encoding: UTF-8
control "V-32526" do
  desc  "rationale", ""
  desc  "check", "
    Review Couchbase settings and vendor documentation to determine whether
Couchbase recognizes session identifiers that are not system-generated.
    If Couchbase recognizes session identifiers that are not system generated,
this is a finding.
  "
  desc  "fix", "Ensure Couchbase only recognizes session identifiers that are
system-generated."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000223-DB-000168"
  tag "gid": "V-32526"
  tag "rid": "SV-42863r2_rule"
  tag "stig_id": "SRG-APP-000223-DB-000168"
  tag "fix_id": "F-36441r2_fix"
  tag "cci": ["CCI-001664"]
  tag "nist": ["SC-23 (3)", "Rev_4"]
end
