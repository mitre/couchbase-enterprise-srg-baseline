# encoding: UTF-8
control "V-58053" do
  desc  "rationale", ""
  desc  "check", "
    Investigate whether there have been any incidents where Couchbase ran out
of audit log space since the last time the space was allocated or other
corrective measures were taken.
    If there have been, this is a finding.
    Review the Couchbase audit settings:
    $ couchbase-cli setting-audit -c <host>:<port> --u <Full Admin> --p
<Password> --get-settings
    If audit-log-rotate-size is not greater than 0, this is a finding
  "
  desc  "fix", "
    Allocate sufficient audit file/table space to support peak demand.
    Configure Couchbase to rotate the log files based on organization defined
standards:
    $ couchbase-cli setting-audit -c <host>:<port> --u  <Full Admin> --p
<Password> --enabled 1 --audit-log-rotate-size <Size>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000357-DB-000316"
  tag "gid": "V-58053"
  tag "rid": "SV-72483r1_rule"
  tag "stig_id": "SRG-APP-000357-DB-000316"
  tag "fix_id": "F-63261r1_fix"
  tag "cci": ["CCI-001849"]
  tag "nist": ["AU-4", "Rev_4"]
end
