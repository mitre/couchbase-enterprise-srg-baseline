# encoding: UTF-8
control "V-58175" do
  desc  "rationale", ""
  desc  "check", "
    Review the list of components and features installed with the Couchbase.
    If unused components are installed and are not documented and authorized,
this is a finding.
    List the currently installed Couchbase packages:
    $ yum list installed | grep couchbase
    If any packages displayed by this command are not being used, this is a
finding.
    If software components that have been replaced or made unnecessary are not
removed, this is a finding.
  "
  desc  "fix", "
    To remove unnecessary software use the following command:
    #yum remove <package-name>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000454-DB-000389"
  tag "gid": "V-58175"
  tag "rid": "SV-72605r1_rule"
  tag "stig_id": "SRG-APP-000454-DB-000389"
  tag "fix_id": "F-63383r1_fix"
  tag "cci": ["CCI-002617"]
  tag "nist": ["SI-2 (6)", "Rev_4"]
end
