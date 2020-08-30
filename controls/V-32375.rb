# encoding: UTF-8
control "V-32375" do
  desc  "rationale", ""
  desc  "check", "
    Review the system documentation to identify what additional information the
organization has determined to be necessary.
    Check Couchbase settings and existing audit records to verify that all
organization-defined additional, more detailed information is in the audit
records for audit events identified by type, location, or subject.
    If any additional information is defined and is not contained in the audit
records, this is a finding.
  "
  desc  "fix", "Configure Couchbase audit settings to include all
organization-defined detailed information in the audit records for audit events
identified by type, location, or subject."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000101-DB-000044"
  tag "gid": "V-32375"
  tag "rid": "SV-42712r4_rule"
  tag "stig_id": "SRG-APP-000101-DB-000044"
  tag "fix_id": "F-36289r3_fix"
  tag "cci": ["CCI-000135"]
  tag "nist": ["AU-3 (1)", "Rev_4"]
end
