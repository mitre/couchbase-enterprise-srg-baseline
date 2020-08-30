# encoding: UTF-8
control "V-58151" do
  desc  "rationale", ""
  desc  "check", "
    Review the permissions granted to users by the operating system/file system
on the database files, database log files and database backup files.
    To verify that all files are owned by the database administrator and have
the correct permissions, run the following:
    $ ls -lR /opt/couchbase/var/lib/couchbase/data
    $ ls -lR /opt/couchbase/etc/couchbase/static_config
    $ ls -IR /opt/couchbase/var/lib/couchbase/logs
    If any files are not owned by couchbase or allow anyone but the couchbase
to read/write/execute, this is a finding.
    If any user/role who is not an authorized system administrator with a need
to know or database administrator with a need to know, or a system account for
running Couchbase processes, is permitted to read/view any of these files, this
is a finding.
  "
  desc  "fix", "
    Configure the permissions granted by the operating system/file system on
the database files, database log files, and database backup files so that only
relevant system accounts and authorized system administrators and database
administrators with a need to know are permitted to read/view these files.
    Any files (for example: extra configuration files) created in the
installation directories must be owned by the authorized system accounts, with
only owner permissions to read, write, and execute.
    Couchbase configuration files directory:
    chown couchbase:couchbase /opt/couchbase/etc/couchbase
    chmod 700 /opt/couchbase/etc/couchbase
    Couchbase default directory (contains data and logs):
    chown -R couchbase:couchbase /opt/couchbase/var/lib/couchbase
    chmod -R 700 /opt/couchbase/var/lib/couchbase
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000243-DB-000374"
  tag "gid": "V-58151"
  tag "rid": "SV-72581r1_rule"
  tag "stig_id": "SRG-APP-000243-DB-000374"
  tag "fix_id": "F-63359r1_fix"
  tag "cci": ["CCI-001090"]
  tag "nist": ["SC-4", "Rev_4"]
end
