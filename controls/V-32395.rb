# encoding: UTF-8
control "V-32395" do
  desc  "rationale", ""
  desc  "check", "
    Review locations of audit logs, both internal to the database and database
audit logs located at the operating system level.
    Review the ownership and permissions of the audit logs:
    $ ls \xE2\x80\x93ald /opt/couchbase/var/lib/couchbase/logs
    If the logs are not owned by both the \"couchbase\" user and group, this is
a finding. If the file permission are not 660, this is a finding.
  "
  desc  "fix", "
    Apply controls and modify permissions to protect database audit log data
from unauthorized deletion, whether stored in the database itself or at the OS
level.
    As the root or sudo user, change the permissions/ownership of the logs
using the following commands:
    $ chown -R couchbase:couchbase /opt/couchbase/var/lib/couchbase/logs
    $ chmod 700 /opt/couchbase/var/lib/couchbase/logs
    $ chmod 660 /opt/couchbase/var/lib/couchbase/*.logs
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000120-DB-000061"
  tag "gid": "V-32395"
  tag "rid": "SV-42732r3_rule"
  tag "stig_id": "SRG-APP-000120-DB-000061"
  tag "fix_id": "F-36310r2_fix"
  tag "cci": ["CCI-000164"]
  tag "nist": ["AU-9", "Rev_4"]
end
