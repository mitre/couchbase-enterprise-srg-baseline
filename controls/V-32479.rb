# encoding: UTF-8
control "V-32479" do
  desc  "rationale", ""
  desc  "check", "
    If all interaction with the user for purposes of authentication is handled
by a software component separate from the Couchbase, this is not a finding.
    As the Full Admin, verify that HTTP access is disabled with the following
command:
      $ curl -v -X GET -u <Full Admin>:<Password>
http://<host>:<port>/settings/security
    Review the output of the command. If \"disableUIOverHttp\" is not set to
\"true\", this is finding.
  "
  desc  "fix", "
    Modify and configure each non-compliant application, tool, or feature
associated with Couchbase/database so that it does not display authentication
secrets.
    As the Full Admin, disable HTTP access to the console and encrypt passwords
with the following command:
     $ curl -v -X GET -u <Full Admin>:<Password>
http://<host>:<port>/settings/security -d disableUIOverHttp=true
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000178-DB-000083"
  tag "gid": "V-32479"
  tag "rid": "SV-42816r4_rule"
  tag "stig_id": "SRG-APP-000178-DB-000083"
  tag "fix_id": "F-36393r3_fix"
  tag "cci": ["CCI-000206"]
  tag "nist": ["IA-6", "Rev_4"]
end
