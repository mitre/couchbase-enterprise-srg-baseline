# encoding: UTF-8

control "V-32423" do
  title "Default demonstration and sample databases, database objects, and
applications must be removed."
  desc  "Information systems are capable of providing a wide variety of
functions and services. Some of the functions and services, provided by
default, may not be necessary to support essential organizational operations
(e.g., key missions, functions).

    It is detrimental for software products to provide, or install by default,
functionality exceeding requirements or mission objectives. Examples include,
but are not limited to, installing advertising software, demonstrations, or
browser plugins not related to requirements or providing a wide array of
functionality, not required for every mission, that cannot be disabled.

    Couchbases must adhere to the principles of least functionality by
providing only essential capabilities.

    Demonstration and sample database objects and applications present publicly
known attack points for malicious users. These demonstration and sample objects
are meant to provide simple examples of coding specific functions and are not
developed to prevent vulnerabilities from being introduced to Couchbase and
host system.
  "
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
