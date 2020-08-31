# encoding: UTF-8
control "V-32529" do
  desc  "rationale", ""
  desc  "check", "
    Check Couchbase settings to determine whether organization-defined system
state information is being preserved in the event of a system failure.
    If organization-defined system state information is not being preserved,
this is a finding.
    As the Full Admin, verify that failover is enabled:
    $ curl -v -X GET -u <Full Admin>:<Password>
http://<host>:<port>/settings/auto-failover
    If auto failover is not enabled, this is a finding
  "
  desc  "fix", "
    Configure Couchbase settings to preserve any organization-defined system
state information in the event of a system failure.
    Review the documentation for automatic failover to specify the settings for
organization-defined use:
    https://docs.couchbase.com/server/current/cli/cbcli/couchbase-cli-setting
autofailover.html
    Enable auto failover and add additional parameters based on organizational
demands:
    couchbase-cli setting-autofailover -c <host>:<port> --u <Full Admin> --p
<Password> --enable-auto-failover 1 <parameters>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000226-DB-000147"
  tag "gid": "V-32529"
  tag "rid": "SV-42866r3_rule"
  tag "stig_id": "SRG-APP-000226-DB-000147"
  tag "fix_id": "F-36444r2_fix"
  tag "cci": ["CCI-001665"]
  tag "nist": ["SC-24", "Rev_4"]
end
