# encoding: UTF-8
control "V-58019" do
  desc  "rationale", ""
  desc  "check", "
    Review system documentation to identify the required discretionary access
control (DAC).
    Review the security configuration of the database and Couchbase. If
applicable, review the security configuration of the application(s) using the
database.
    If the discretionary access control defined in the documentation is not
implemented in the security configuration, this is a finding.
    Review Couchbase functionality considered privileged in the context of the
system in question.
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
--list
    If any functionality considered privileged has access privileges granted to
non-privileged users, this is a finding.
  "
  desc  "fix", "Implement the organization's DAC policy in the security
configuration of the database and Couchbase, and, if applicable, the security
configuration of the application(s) using the database."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000328-DB-000301"
  tag "gid": "V-58019"
  tag "rid": "SV-72449r1_rule"
  tag "stig_id": "SRG-APP-000328-DB-000301"
  tag "fix_id": "F-63227r1_fix"
  tag "cci": ["CCI-002165"]
  tag "nist": ["AC-3 (4)", "Rev_4"]
end
