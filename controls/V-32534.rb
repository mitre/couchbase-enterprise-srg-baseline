# encoding: UTF-8
control "V-32534" do
  desc  "rationale", ""
  desc  "check", "
    If the application owner and Authorizing Official have determined that
encryption of data at rest is NOT required, this is not a finding.
    If an encryption at rest is required but the encryption tool is not
installed on the server, this is a finding.
  "
  desc  "fix", "
    Apply appropriate controls to protect the confidentiality and integrity of
data at rest in the database.
    Review  documentation to set up 3rd party encryption tools.
https://docs.couchbase.com/server/current/manage/manage-security/manage-connections-and-disks.html
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000231-DB-000154"
  tag "gid": "V-32534"
  tag "rid": "SV-42871r4_rule"
  tag "stig_id": "SRG-APP-000231-DB-000154"
  tag "fix_id": "F-36449r2_fix"
  tag "cci": ["CCI-001199"]
  tag "nist": ["SC-28", "Rev_4"]
end
