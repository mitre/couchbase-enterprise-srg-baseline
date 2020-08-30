# encoding: UTF-8
control "V-58165" do
  desc  "rationale", ""
  desc  "check", "
    Verify Couchbase has SSL enabled:
    $ couchbase-cli ssl-manage -c <localhost>:<port> -u <Full Admin> \\-p
<Password> --client-auth --extended
    If Couchbase does not have SSL enabled, this is a finding.
    Review Couchbase settings to determine whether protections against
man-in-the-middle attacks that guess at session identifier values are enabled.
    If they are not, this is a finding.

  "
  desc  "fix", "
    To make authorization mandatory run the following command:
    $ couchbase-cli ssl-manage -c <localhost>:<port> -u <Full Admin>\\ -p
<Password> --set-client-auth mandatory
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-DB-000384"
  tag "gid": "V-58165"
  tag "rid": "SV-72595r1_rule"
  tag "stig_id": "SRG-APP-000224-DB-000384"
  tag "fix_id": "F-63373r1_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]
end
