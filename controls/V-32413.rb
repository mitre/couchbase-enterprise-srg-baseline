# encoding: UTF-8
control "V-32413" do
  desc  "rationale", ""
  desc  "check", "
    If Couchbase is running within a Docker container, this is not a finding.
    Review the Couchbase software library directory and note other root
directories located on the same disk directory or any subdirectories.
    If any non-Couchbase software directories exist on the disk directory,
examine or investigate their use. If any of the directories are used by other
applications, including third-party applications that use Couchbase, this is a
finding.
    Only applications that are required for the functioning and administration,
not use, of the Couchbase should be located in the same disk directory as the
Couchbase software libraries.
    If other applications are located in the same directory as Couchbase, this
is a finding.
  "
  desc  "fix", "Install all applications on directories separate from the
Couchbase software library directory. Relocate any directories or reinstall
other application software that currently shares the Couchbase software library
directory."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000199"
  tag "gid": "V-32413"
  tag "rid": "SV-42750r3_rule"
  tag "stig_id": "SRG-APP-000133-DB-000199"
  tag "fix_id": "F-36328r2_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
end
