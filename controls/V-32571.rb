# encoding: UTF-8
control "V-32571" do
  desc  "rationale", ""
  desc  "check", "
    Check Couchbase settings and custom database code to determine if detailed
error messages are ever displayed to unauthorized individuals.
    Review the ownership and permissions of the audit logs:
      $ ls \xE2\x80\x93ald /opt/couchbase/var/lib/couchbase/logs
    If the logs are not owned by both the \"couchbase\" user and group, this is
a finding. If the file permission are not 600, this is a finding.
  "
  desc  "fix", "
    As the root or sudo user, change the permissions/ownership of the logs
using the following commands:
      $ chown -R couchbase:couchbase /opt/couchbase/var/lib/couchbase/logs
      $ chmod 700 /opt/couchbase/var/lib/couchbase/logs
      $ chmod 600 /opt/couchbase/var/lib/couchbase/*.logs
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000267-DB-000163"
  tag "gid": "V-32571"
  tag "rid": "SV-42908r5_rule"
  tag "stig_id": "SRG-APP-000267-DB-000163"
  tag "fix_id": "F-36486r2_fix"
  tag "cci": ["CCI-001314"]
  tag "nist": ["SI-11 b", "Rev_4"]
end
