# encoding: UTF-8
control "V-58025" do
  desc  "rationale", ""
  desc  "check", "
    Review system documentation to obtain the organization's definition of
circumstances requiring automatic session termination. If the documentation
explicitly states that such termination is not required or is prohibited, this
is not a finding.
    As the Full Admin, get the current security settings with the following
command:
    $ curl -v -X GET -u <Full Admin>:<Password>
http://<host>:<port>/settings/security
    Review the output of the command. If uiSessionTimeout does not have a
value, this is a finding.

  "
  desc  "fix", "
    Configure Couchbase to automatically terminate a user session after
organization-defined conditions or trigger events requiring session termination.
    As the Full Admin, configure session timeout:
    $ curl -X POST -u  <Full Admin>:<Password>\\
http://<host>:<port>/settings/security \\ -d \"uiSessionTimeout=600\"
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000295-DB-000305"
  tag "gid": "V-58025"
  tag "rid": "SV-72455r1_rule"
  tag "stig_id": "SRG-APP-000295-DB-000305"
  tag "fix_id": "F-63233r1_fix"
  tag "cci": ["CCI-002361"]
  tag "nist": ["AC-12", "Rev_4"]
end
