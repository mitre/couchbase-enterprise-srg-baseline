# encoding: UTF-8
control "V-58057" do
  desc  "rationale", ""
  desc  "check", "
    Review system configuration.
    If no script/tool is monitoring the partition for the Couchbase log
directories, this is a finding.
    If appropriate support staff are not notified immediately upon storage
volume utilization reaching 75%, this is a finding.
  "
  desc  "fix", "Configure Couchbase to notify appropriate support staff
immediately upon storage volume utilization reaching 75%."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000359-DB-000319"
  tag "gid": "V-58057"
  tag "rid": "SV-72487r1_rule"
  tag "stig_id": "SRG-APP-000359-DB-000319"
  tag "fix_id": "F-63265r1_fix"
  tag "cci": ["CCI-001855"]
  tag "nist": ["AU-5 (1)", "Rev_4"]
end
