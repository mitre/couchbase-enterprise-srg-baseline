# encoding: UTF-8
control "V-58157" do
  desc  "rationale", ""
  desc  "check", "
    If Couchbase is deployed in an unclassified environment, this is not
applicable (NA).
    If Couchbase is not using NSA-approved cryptography to protect classified
information in accordance with applicable federal laws, Executive Orders,
directives, policies, regulations, and standards, this is a finding.
    Verify Couchbase has SSL enabled:
    $ couchbase-cli ssl-manage -c <host>:<port>-u Administrator -p password
--client-auth --extended
    If the response does not show SSL is enabled, this is a finding.
  "
  desc  "fix", "
    Configure Couchbase and related system components to use NSA-approved
cryptography to protect classified information in accordance with applicable
federal laws, Executive Orders, directives, policies, regulations, and
standards.
    Configure Couchbase to enforce SSL:
    $ couchbase-cli ssl-manage -c <host>:<port> -u <Full Admin> -p <Password>
--set-client-auth <Config File>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000416-DB-000380"
  tag "gid": "V-58157"
  tag "rid": "SV-72587r1_rule"
  tag "stig_id": "SRG-APP-000416-DB-000380"
  tag "fix_id": "F-63365r1_fix"
  tag "cci": ["CCI-002450"]
  tag "nist": ["SC-13", "Rev_4"]
end
