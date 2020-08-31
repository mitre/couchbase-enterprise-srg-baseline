# encoding: UTF-8
control "V-32414" do
  desc  "rationale", ""
  desc  "check", "
    Review procedures for controlling, granting access to, and tracking use of
the Couchbase software installation account.
    If access or use of this account is not restricted to the minimum number of
personnel required or if unauthorized access to the account has been granted,
this is a finding.
  "
  desc  "fix", "Develop, document, and implement procedures to restrict and
track use of the Couchbase software installation account."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000198"
  tag "gid": "V-32414"
  tag "rid": "SV-42751r3_rule"
  tag "stig_id": "SRG-APP-000133-DB-000198"
  tag "fix_id": "F-36329r2_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
end
