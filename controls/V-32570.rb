# encoding: UTF-8
control "V-32570" do
  desc  "rationale", ""
  desc  "check", "
    Check Couchbase settings and custom database code to verify that error
messages do not contain information beyond what is needed for troubleshooting
the issue.
    If database errors contain PII data, sensitive business data, or
information useful for identifying the host system or database structure, this
is a finding.
  "
  desc  "fix", "Configure Couchbase settings, custom database code, and
associated application code not to divulge sensitive information or information
useful for system identification in error messages."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000266-DB-000162"
  tag "gid": "V-32570"
  tag "rid": "SV-42907r4_rule"
  tag "stig_id": "SRG-APP-000266-DB-000162"
  tag "fix_id": "F-36485r2_fix"
  tag "cci": ["CCI-001312"]
  tag "nist": ["SI-11 a", "Rev_4"]
end
