# encoding: UTF-8
control "V-58039" do
  desc  "rationale", ""
  desc  "check", "
    If security labeling is not required, this is not a finding.
    If security labeling requirements have been specified, but the security
labeling is not implemented or does not reliably maintain labels on information
in process, this is a finding.
  "
  desc  "fix", "Enable Couchbase features, deploy third-party software, or add
custom data structures, data elements and application code, to provide reliable
security labeling of information in process."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000313-DB-000309"
  tag "gid": "V-58039"
  tag "rid": "SV-72469r1_rule"
  tag "stig_id": "SRG-APP-000313-DB-000309"
  tag "fix_id": "F-63247r1_fix"
  tag "cci": ["CCI-002263"]
  tag "nist": ["AC-16 a", "Rev_4"]
end
