# encoding: UTF-8
control "V-32468" do
  desc  "rationale", ""
  desc  "check", "
    If password authentication is used, SCRAM-SHA1, SCRAM-SHA256, and
SCRAM-SHA512,  authentication protocols are available with saslauthd enabled.
These protocols use one-way, salted hash functions for passwords as documented
here:
https://docs.couchbase.com/server/current/learn/security/authentication-overview.html
    As Full Admin, execute the following command to check if saslauthd is
enabled:
      $ curl -X GET -u <Full Admin>:<Password>
http://<host>:<port>/settings/saslauthdAuth
    If saslauthd it is not enabled, this is a finding.

  "
  desc  "fix", "
    As the Full Admin, enable saslauthd with the following command:
      $ couchbase-cli setting-saslauthd -c <host>:<port> --username <Full
Admin> \\
     --password <Password> --enabled 1
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000171-DB-000074"
  tag "gid": "V-32468"
  tag "rid": "SV-42805r3_rule"
  tag "stig_id": "SRG-APP-000171-DB-000074"
  tag "fix_id": "F-36383r4_fix"
  tag "cci": ["CCI-000196"]
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]
end
