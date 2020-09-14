# encoding: UTF-8

control "V-58151" do
  title "Access to database files must be limited to relevant processes and to
  authorized, administrative users."
  desc  "Applications, including Couchbases, must prevent unauthorized and
  unintended information transfer via shared system resources. Permitting only
  Couchbase processes and authorized, administrative users to have access to the
  files where the database resides helps ensure that those files are not shared
  inappropriately and are not open to backdoor access and manipulation.
  "
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
    $ chown -R couchbase:couchbase /opt/couchbase/etc/couchbase
    $ chmod 700 /opt/couchbase/etc/couchbase
  Couchbase default directory (contains data and logs):
    $ chown -R couchbase:couchbase /opt/couchbase/var/lib/couchbase
    $ chmod -R 700 /opt/couchbase/var/lib/couchbase
  Couchbase default directory (contains data and logs):
    $ chown -R couchbase:couchbase /opt/couchbase/var/lib/couchbase
    $ chmod -R 700 /opt/couchbase/var/lib/couchbase/static_config
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

  describe file(input('cb_static_config')) do
    its('owner') { should be_in input('cb_service_user') }
    its('group') { should be_in input('cb_service_group') }
    it { should_not be_more_permissive_than('0600') }
  end      
  describe directory(input('cb_data_dir')) do
    it { should be_directory }
    its('owner') { should be_in input('cb_service_user') }
    its('group') { should be_in input('cb_service_group') }
    it { should_not be_more_permissive_than('0700') }
  end
  describe directory(input('cb_log_dir')) do
    it { should be_directory }
    its('owner') { should be_in input('cb_service_user') }
    its('group') { should be_in input('cb_service_group') }
    it { should_not be_more_permissive_than('0700') }
  end   
end

