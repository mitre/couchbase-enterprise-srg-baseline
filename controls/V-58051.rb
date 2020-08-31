# encoding: UTF-8
control "V-58051" do
  desc  "rationale", ""
  desc  "check", "
    Couchbase allows centralized configuration of auditing through the web
console.
    Verify that the web console is not disabled.
    As the Full Admin, verify that HTTPS access is not disabled with the
following command:
     $ curl -v -X GET -u <Full Admin>:<Password>
http://<host>:<port>/settings/security
    Review the output of the command. If \"disableUIOverHttps\" is set to
\"true\", this is finding.
  "
  desc  "fix", "
    Modify and configure each non-compliant application, tool, or feature
associated with Couchbase/database so that it does not display authentication
secrets.
    The web console is available by default, unless both \"disableUIOverHttp\"
and \"disableUIOverHttps\" are both set to \"true\".
    If \"disableUIOverHttps\" is set to \"true\", as the Full Admin, change
this value to \"false\" with the following command:
     $  curl -v -X GET -u <Full Admin>:<Password>
http://<host>:<port>/settings/security -d disableUIOverHttps=false

  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000356-DB-000315"
  tag "gid": "V-58051"
  tag "rid": "SV-72481r1_rule"
  tag "stig_id": "SRG-APP-000356-DB-000315"
  tag "fix_id": "F-63259r1_fix"
  tag "cci": ["CCI-001844"]
  tag "nist": ["AU-3 (2)", "Rev_4"]
end
