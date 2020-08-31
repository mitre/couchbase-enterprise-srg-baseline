# encoding: UTF-8
control "V-32547" do
  desc  "rationale", ""
  desc  "check", "
    Review the procedures for the refreshing of development/test data from
production.
    Review any scripts or code that exists for the movement of production data
to development/test systems, or to any other location or for any other purpose.
    Verify that copies of production data are not left in unprotected
locations.
    If the code that exists for data movement does not comply with the
organization-defined data transfer policy and/or fails to remove any copies of
production data from unprotected locations, this is a finding.
  "
  desc  "fix", "Modify any code used for moving data from production to
development/test systems to comply with the organization-defined data transfer
policy, and to ensure copies of production data are not left in unsecured
locations."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000243-DB-000128"
  tag "gid": "V-32547"
  tag "rid": "SV-42884r3_rule"
  tag "stig_id": "SRG-APP-000243-DB-000128"
  tag "fix_id": "F-36462r3_fix"
  tag "cci": ["CCI-001090"]
  tag "nist": ["SC-4", "Rev_4"]
end
