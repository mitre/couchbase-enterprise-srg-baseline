# encoding: UTF-8
control "V-58147" do
  desc  "rationale", ""
  desc  "check", "Review the organization-defined circumstances or situations
and determine all situations where a user must re-authenticate. If there are
any of these organization-defined circumstances under which a user is not
required to re-authenticate, this is a finding."
  desc  "fix", "Modify and/or configure Couchbase and related applications and
tools so that users are always required to re-authenticate when the specified
cases needing reauthorization occur."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000389-DB-000372"
  tag "gid": "V-58147"
  tag "rid": "SV-72577r1_rule"
  tag "stig_id": "SRG-APP-000389-DB-000372"
  tag "fix_id": "F-63355r1_fix"
  tag "cci": ["CCI-002038"]
  tag "nist": ["IA-11", "Rev_4"]
end
