# encoding: UTF-8
control "V-58155" do
  desc  "rationale", ""
  desc  "check", "
    If Couchbase is deployed in an unclassified environment, this is not
applicable (NA).
    If Couchbase is not maintaining the confidentiality and integrity of
information during receptions, this is a finding.
    Verify Couchbase has SSL enabled:
    $ couchbase-cli ssl-manage -c <host>:<port>-u Administrator -p password
--client-auth --extended
    If the response does not show SSL is enabled, this is a finding.
  "
  desc  "fix", "
    Implement protective measures against unauthorized disclosure and
modification during reception.
    Configure Couchbase to enforce SSL:
    $ couchbase-cli ssl-manage -c <host>:<port> -u <Full Admin> -p <Password>
--set-client-auth <Config File>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000442-DB-000379"
  tag "gid": "V-58155"
  tag "rid": "SV-72585r1_rule"
  tag "stig_id": "SRG-APP-000442-DB-000379"
  tag "fix_id": "F-63363r1_fix"
  tag "cci": ["CCI-002422"]
  tag "nist": ["SC-8 (2)", "Rev_4"]
end
