# encoding: UTF-8
control "V-58181" do
  desc  "rationale", ""
  desc  "check", "
    Review Couchbase source code (stored procedures, functions, triggers) and
application source code to identify cases of dynamic code execution.
    If dynamic code execution is employed without protective measures against
code injection, this is a finding.
  "
  desc  "fix", "Where dynamic code execution is used, modify the code to
implement protections against code injection."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000251-DB-000392"
  tag "gid": "V-58181"
  tag "rid": "SV-72611r2_rule"
  tag "stig_id": "SRG-APP-000251-DB-000392"
  tag "fix_id": "F-63389r1_fix"
  tag "cci": ["CCI-001310"]
  tag "nist": ["SI-10", "Rev_4"]
end
