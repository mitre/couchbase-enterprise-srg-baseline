# encoding: UTF-8
control "V-32383" do
  desc  "rationale", ""
  desc  "check", "
    If the application owner has determined that the need for system
availability outweighs the need for a complete audit trail, this is not
applicable (NA).
    Review Couchbase, OS, or third-party logging application settings and/or
documentation to determine whether the system is capable of shutting down,
rolling back all in-flight transactions, in the case of an auditing failure. If
it is not, this is a finding.
    If the system is capable of shutting down upon audit failure but is not
configured to do so, this is a finding.
  "
  desc  "fix", "Configure the system to shut down, rolling back all in-flight
transactions, in the case of an auditing failure."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000109-DB-000049"
  tag "gid": "V-32383"
  tag "rid": "SV-42720r3_rule"
  tag "stig_id": "SRG-APP-000109-DB-000049"
  tag "fix_id": "F-36298r2_fix"
  tag "cci": ["CCI-000140"]
  tag "nist": ["AU-5 b", "Rev_4"]
end
