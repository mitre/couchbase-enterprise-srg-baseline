# encoding: UTF-8
control "V-58177" do
  desc  "rationale", ""
  desc  "check", "
    Obtain evidence that software patches are consistently applied to Couchbase
within the time frame defined for each patch.
    To list the current version of Couchbase installed:
    #couchbase-cli --version
    Verify the version is the most recent available by visiting the following
link:
    https://docs.couchbase.com/server/current/release-notes/relnotes.html
    If the current Couchbase version is not the latest this is a finding.
  "
  desc  "fix", "
    Institute and adhere to policies and procedures to ensure that patches are
consistently applied to Couchbase within the time allowed.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000456-DB-000390"
  tag "gid": "V-58177"
  tag "rid": "SV-72607r1_rule"
  tag "stig_id": "SRG-APP-000456-DB-000390"
  tag "fix_id": "F-63385r1_fix"
  tag "cci": ["CCI-002605"]
  tag "nist": ["SI-2 c", "Rev_4"]
end
