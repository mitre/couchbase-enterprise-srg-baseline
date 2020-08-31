# encoding: UTF-8
control "V-32423" do
  desc  "rationale", ""
  desc  "check", "
    Review Couchbase to determine if any of the demonstration and sample
databases, database applications, or files are installed in the database or are
included with the Couchbase application.
    As the Full Admin, execute the following commands to list all buckets on
the cluster:
      $ couchbase-cli bucket-list -c <host>:<port> --username <Full Admin> \\
     --password <Password>
    If any are any sample buckets included with the Couchbase application, this
is a finding.
  "
  desc  "fix", "
    Remove any demonstration and sample buckets from Couchbase.
    As the Full Admin, execute the following commands to delete sample buckets
from the cluster:
    couchbase-cli bucket-delete <host>:<port> --username <Full Admin> \\
     --password <Password>  --bucket <name>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000090"
  tag "gid": "V-32423"
  tag "rid": "SV-42760r3_rule"
  tag "stig_id": "SRG-APP-000141-DB-000090"
  tag "fix_id": "F-36338r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
end
