# encoding: UTF-8
control "V-32424" do
  desc  "rationale", ""
  desc  "check", "
    Review the list of components and features installed with the Couchbase
database.
    $ yum list installed | grep couchbase
    If unused components are installed and are not documented and authorized,
this is a finding.
    RPM can also be used to check to see what is installed:
    $  rpm -qa | grep couchbase
    If any packages displayed by this command are not being used, this is a
finding.
  "
  desc  "fix", "Uninstall unused components or features that are installed and
can be uninstalled. Remove any database objects and applications that are
installed to support them."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000091"
  tag "gid": "V-32424"
  tag "rid": "SV-42761r3_rule"
  tag "stig_id": "SRG-APP-000141-DB-000091"
  tag "fix_id": "F-36339r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
end
