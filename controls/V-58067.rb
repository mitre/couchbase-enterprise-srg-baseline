# encoding: UTF-8
control "V-58067" do
  desc  "rationale", ""
  desc  "check", "
    If Couchbase does not provide the ability for users in authorized roles to
reconfigure auditing at any time of the user's choosing, this is a finding.
    If changes in audit configuration cannot take effect until after a certain
time or date, or until some event, such as a server restart, has occurred, and
if that time or event does not meet the requirements specified by the
application owner, this is a finding.
  "
  desc  "fix", "
    Deploy a Couchbase database that provides the ability for users in
authorized roles to reconfigure auditing at any time.
    Deploy a Couchbase that allows audit configuration changes to take effect
within the timeframe required by the application owner and without involving
actions or events that the application owner rules unacceptable.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000353-DB-000324"
  tag "gid": "V-58067"
  tag "rid": "SV-72497r1_rule"
  tag "stig_id": "SRG-APP-000353-DB-000324"
  tag "fix_id": "F-63275r1_fix"
  tag "cci": ["CCI-001914"]
  tag "nist": ["AU-12 (3)", "Rev_4"]
end
