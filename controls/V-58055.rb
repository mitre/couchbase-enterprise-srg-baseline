# encoding: UTF-8

control "V-58055" do
  title "Couchbase must off-load audit data to a separate log management
facility; this shall be continuous and in near real time for systems with a
network connection to the storage facility and weekly or more often for
stand-alone systems."
  desc  "Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    Couchbase may write audit records to database tables, to files in the file
system, to other kinds of local repository, or directly to a centralized log
management system. Whatever the method used, it must be compatible with
off-loading the records to the centralized system.
  "
  desc  "rationale", ""
  desc  "check", "
    Review the system documentation for a description of how audit records are
off-loaded.
    If Couchbase has a continuous network connection to the centralized log
management system, but Couchbase audit records are not written directly to the
centralized log management system or transferred in near-real-time, this is a
finding.
    If Couchbase does not have a continuous network connection to the
centralized log management system, and Couchbase  audit records are not
transferred to the centralized log management system weekly or more often, this
is a finding.
  "
  desc  "fix", "Configure Couchbase or deploy and configure software tools to
transfer audit records to a centralized log management system, continuously and
in near-real time where a continuous network connection to the log management
system exists, or at least weekly in the absence of such a connection."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000515-DB-000318"
  tag "gid": "V-58055"
  tag "rid": "SV-72485r1_rule"
  tag "stig_id": "SRG-APP-000515-DB-000318"
  tag "fix_id": "F-63263r1_fix"
  tag "cci": ["CCI-001851"]
  tag "nist": ["AU-4 (1)", "Rev_4"]
end
