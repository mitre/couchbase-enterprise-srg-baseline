# encoding: UTF-8
control "V-58035" do
  desc  "rationale", ""
  desc  "check", "
    Determine, by reviewing Couchbase documentation and/or inquiring of the
vendor's technical support staff, whether the Couchbase satisfies this
requirement; and, if it does, determine whether this is inherent, unchangeable
behavior, or a configurable feature.
    If Couchbase does not satisfy the requirement, this is a permanent finding.
    If the behavior is inherent, this is permanently not a finding.
    If the behavior is configurable, and the current configuration does not
enforce it, this is a finding.
  "
  desc  "fix", "Where relevant, modify the configuration to allow the user to
manually terminate a session initiated by that user."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000296-DB-000306"
  tag "gid": "V-58035"
  tag "rid": "SV-72465r1_rule"
  tag "stig_id": "SRG-APP-000296-DB-000306"
  tag "fix_id": "F-63243r1_fix"
  tag "cci": ["CCI-002363"]
  tag "nist": ["AC-12 (1)", "Rev_4"]
end
