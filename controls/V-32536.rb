# encoding: UTF-8
control "V-32536" do
  desc  "rationale", ""
  desc  "check", "
    Check Couchbase settings to determine whether objects or code implementing
security functionality are located in a separate security domain, such as a
separate database or schema created specifically for security functionality.
    If security-related database objects or code are not kept separate, this is
a finding.
  "
  desc  "fix", "Locate security-related database objects and code in a separate
database, schema, or other separate security domain from database objects and
code implementing application logic."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000233-DB-000124"
  tag "gid": "V-32536"
  tag "rid": "SV-42873r3_rule"
  tag "stig_id": "SRG-APP-000233-DB-000124"
  tag "fix_id": "F-36451r2_fix"
  tag "cci": ["CCI-001084"]
  tag "nist": ["SC-3", "Rev_4"]
end
