# encoding: UTF-8

control "V-58137" do
  title "Couchbase must prohibit the use of cached authenticators after an
organization-defined time period."
  desc  "If cached authentication information is out-of-date, the validity of
the authentication information may be questionable."
  desc  "check", "
    Review system settings to determine whether the organization-defined limit
for cached authentication is implemented.
    If Couchbase is configured to authenticate using LDAP verify that the
\"cache-value-lifetime\" value is set to an organization-defined time period.
    As the Full Admin, get the current settings with the following command:
    $ curl -v -X GET -u <Full Admin>:<Password>
http://<host>:<port>:settings/ldap
    If cache-value-lifetime is not set, this is a finding.
  "
  desc  "fix", "
    Modify system settings to implement the organization-defined limit on the
lifetime of cached authenticators.
    $ couchbase-cli setting-ldap -c <host>:<port>-u <Full Admin> -p <Password>
--cache-value-lifetime <ms>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000400-DB-000367"
  tag "gid": "V-58137"
  tag "rid": "SV-72567r1_rule"
  tag "stig_id": "SRG-APP-000400-DB-000367"
  tag "fix_id": "F-63345r1_fix"
  tag "cci": ["CCI-002007"]
  tag "nist": ["IA-5 (13)", "Rev_4"]
end
