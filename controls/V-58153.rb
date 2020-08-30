# encoding: UTF-8
control "V-58153" do
  desc  "rationale", ""
  desc  "check", "
    Review the system information/specification for information indicating a
strict requirement for data integrity and confidentiality when data is being
prepared to be transmitted.
    If the Couchbase does not employ protective measures against unauthorized
disclosure and modification during preparation for transmission, this is a
finding.
    Verify Couchbase has SSL enabled:
    $ couchbase-cli ssl-manage -c <host>:<port> -u <Full Admin> -p <Password>
--client-auth --extended
    If the response does not show SSL is enabled, this is a finding.
  "
  desc  "fix", "
    Implement protective measures against unauthorized disclosure and
modification during preparation for transmission.
    Configure Couchbase to enforce SSL:
    $ couchbase-cli ssl-manage -c <host>:<port> -u <Full Admin> -p <Password>
--set-client-auth <Config File>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000441-DB-000378"
  tag "gid": "V-58153"
  tag "rid": "SV-72583r1_rule"
  tag "stig_id": "SRG-APP-000441-DB-000378"
  tag "fix_id": "F-63361r1_fix"
  tag "cci": ["CCI-002420"]
  tag "nist": ["SC-8 (2)", "Rev_4"]
end
