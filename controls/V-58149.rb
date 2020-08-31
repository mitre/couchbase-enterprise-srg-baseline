# encoding: UTF-8

control "V-58149" do
  title "Couchbase must prevent unauthorized and unintended information
transfer via shared system resources."
  desc  "The purpose of this control is to prevent information, including
encrypted representations of information, produced by the actions of a prior
user/role (or the actions of a process acting on behalf of a prior user/role)
from being available to any current user/role (or current process) that obtains
access to a shared system resource (e.g., registers, main memory, secondary
storage) after the resource has been released back to the information system.
Control of information in shared resources is also referred to as object reuse."
  desc  "rationale", ""
  desc  "check", "
    Review the permissions granted to users by the operating system/file system
on the database files, database log files and database backup files.
    Verify the permissions for the following database files directories with
the following commands:
    Couchbase configuration files directory -
     $ ls -la /opt/couchbase/etc/couchbase
    Couchbase default directory (contains data and logs):
      $ ls -la /opt/couchbase/var/lib/couchbase
    If the owner and group are not both \"couchbase\" for the files, this is a
finding.
    If the files permissions are more permissive than \"600\", this is a
finding.
  "
  desc  "fix", "
    Configure Couchbase to effectively protect the private resources of one
process or user from unauthorized access by another user or process.
    As the root or sudo user, change the permission of the following files:
    Couchbase configuration files directory:
      $ chown -R couchbase:couchbase /opt/couchbase/etc/couchbase
      $ chmod 600 /opt/couchbase/etc/couchbase/*
    Couchbase default directory (contains data and logs):
      $ chown -R couchbase:couchbase /opt/couchbase/var/lib/couchbase
      $ chmod 600 /opt/couchbase/var/lib/couchbase/*
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000243-DB-000373"
  tag "gid": "V-58149"
  tag "rid": "SV-72579r1_rule"
  tag "stig_id": "SRG-APP-000243-DB-000373"
  tag "fix_id": "F-63357r1_fix"
  tag "cci": ["CCI-001090"]
  tag "nist": ["SC-4", "Rev_4"]
end
