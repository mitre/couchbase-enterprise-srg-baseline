# encoding: UTF-8
control "V-58179" do
  desc  "rationale", ""
  desc  "check", "
    Review Couchbase source code (stored procedures, functions, triggers) and
application source code, to identify cases of dynamic code execution.
    If dynamic code execution is employed in circumstances where the objective
could practically be satisfied by static execution with strongly typed
parameters, this is a finding.
  "
  desc  "fix", "Where dynamic code execution is employed in circumstances where
the objective could practically be satisfied by static execution with strongly
typed parameters, modify the code to do so."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000251-DB-000391"
  tag "gid": "V-58179"
  tag "rid": "SV-72609r2_rule"
  tag "stig_id": "SRG-APP-000251-DB-000391"
  tag "fix_id": "F-63387r1_fix"
  tag "cci": ["CCI-001310"]
  tag "nist": ["SI-10", "Rev_4"]
end
