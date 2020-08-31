# encoding: UTF-8
control "V-32428" do
  desc  "rationale", ""
  desc  "check", "Review Couchbase settings and local documentation for
functions, ports, protocols, and services that are not approved. If any are
found, this is a finding."
  desc  "fix", "Disable functions, ports, protocols, and services that are not
approved."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000142-DB-000094"
  tag "gid": "V-32428"
  tag "rid": "SV-42765r3_rule"
  tag "stig_id": "SRG-APP-000142-DB-000094"
  tag "fix_id": "F-36342r2_fix"
  tag "cci": ["CCI-000382"]
  tag "nist": ["CM-7 b", "Rev_4"]
end
