# encoding: UTF-8
control "V-32426" do
  desc  "rationale", ""
  desc  "check", "
    To list all installed packages, as the system administrator, run the
following:
    # RHEL/CENT Systems
    $ yum list installed | grep couchbase
    # Debian Systems
    $ dpkg --get-selections | grep couchbase
    If any packages are installed that are not required, this is a finding.
  "
  desc  "fix", "
    To remove any unneeded executables, as the system administrator, run the
following:
    # RHEL/CENT Systems
    $ yum remove <package_name>
    # Debian Systems
    $ apt-get remove <package_name>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000092"
  tag "gid": "V-32426"
  tag "rid": "SV-42763r4_rule"
  tag "stig_id": "SRG-APP-000141-DB-000092"
  tag "fix_id": "F-36340r3_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
end
