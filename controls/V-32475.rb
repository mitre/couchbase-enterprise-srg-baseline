# encoding: UTF-8
control "V-32475" do
  desc  "rationale", ""
  desc  "check", "
    If Couchbase is not using PKI-based authentication, this check is Not
Applicable (NA).
    As the Full Admin, verify that that path validating is being performed with
the following command:
    $ couchbase-cli ssl-manage -c <host>:<port> -u <Full Admin> -p <Password>
--client-auth --extended
    Review the output. If it does not contain the \"path\" prefix, this is a
finding.
  "
  desc  "fix", "
    As the Full Admin, configure Couchbase to validate certificates by
performing RFC 5280-compliant certification path validation with the following
command:
      $ couchbase-cli ssl-manage -c <host>:<port> -u <Full Admin> -p <Password>
--set-client-auth <Auth Config File>
    Example:
    {
      \"state\": \"enable\",
      \"prefixes\": [
        {
          \"path\": \"subject.cn\",
          \"prefix\": \"www.cb-\",
          \"delimiter\": \".\"
        }
      ]
    }
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000175-DB-000067"
  tag "gid": "V-32475"
  tag "rid": "SV-42812r3_rule"
  tag "stig_id": "SRG-APP-000175-DB-000067"
  tag "fix_id": "F-36390r3_fix"
  tag "cci": ["CCI-000185"]
  tag "nist": ["IA-5 (2) (a)", "Rev_4"]
end
