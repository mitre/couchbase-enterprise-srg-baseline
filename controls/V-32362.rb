# encoding: UTF-8
control "V-32362" do
  desc  "rationale", ""
  desc  "check", "
    Check Couchbase auditing to determine whether organization-defined
auditable events are being audited by the system.
    To verify other events being audited do the following:
    Couchbase Server 6.5.0 and earlier -
      As the Full Admin, log into the cluster to verify which events are
disabled and which are enabled. Use  the following documentation:
      -
https://docs.couchbase.com/server/6.0/manage/manage-security/manage-auditing.html
    Couchbase Server Version 6.51 and later -
    When auditing is enabled, the following events are audited by default and
cannot be turned off:
      - authentication failed
      - command access failed
      - privilege debug configured
      - privilege debug
      As the Full Admin, execute the following command to verify which events
are disabled and which are enabled:
       $ couchbase-cli setting-audit -c <host>:<port> -u <Full Admin> -p
<Password> --get-settings
    If organization-defined auditable events are not being audited, this is a
finding.
  "
  desc  "fix", "
    Deploy a Couchbase database that supports the DoD minimum set of auditable
events.
    Enable the required set of auditable events by doing the following:
    Couchbase Server 6.5.0 and earlier -
      As the Full Admin, log into the cluster and use  the following
documentation to enable required events:
      -
https://docs.couchbase.com/server/6.0/manage/manage-security/manage-auditing.html
      -
https://docs.couchbase.com/server/6.5/manage/manage-security/manage-auditing.html
    Couchbase Server 6.5.1 and later -
      As the Full Admin, log into the cluster and use the following
documentation to enable required events:
      -
https://docs.couchbase.com/server/6.5/manage/manage-security/manage-auditing.html
      -
https://docs.couchbase.com/server/6.6/manage/manage-security/manage-auditing.html

  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000089-DB-000064"
  tag "gid": "V-32362"
  tag "rid": "SV-42699r3_rule"
  tag "stig_id": "SRG-APP-000089-DB-000064"
  tag "fix_id": "F-36277r2_fix"
  tag "cci": ["CCI-000169"]
  tag "nist": ["AU-12 a", "Rev_4"]
end
