# encoding: UTF-8
control "V-58183" do
  desc  "rationale", ""
  desc  "check", "
    Review system documentation to determine how input errors are to be handled
in general and if any special handling is defined for specific circumstances.
    Review the source code for database program objects (stored procedures,
functions, triggers) and application source code to identify how the system
responds to invalid input.
    As database administrator, make a small syntax error (missing key word FROM
before dataset TestDatabase):
      $ cbq -u <Full Admin> -p <Password> -engine=http://<host>:<port>/
--script=\"SELECT * TestDatabase user\"
    Verify the syntax error was logged by Couchbase (change the log file name
and part to suit the circumstances).
    $ cat /opt/couchbase/var/lib/couchbase/logs/event.log
    If it does not implement the documented behavior, this is a finding.
  "
  desc  "fix", "
    Configure Couchbase to generate audit records for all invalid inputs.
    Edit the configuration file and set all log components to the error level.
      $ vi /opt/couchbase/etc/couchbase/static_config
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000447-DB-000393"
  tag "gid": "V-58183"
  tag "rid": "SV-72613r2_rule"
  tag "stig_id": "SRG-APP-000447-DB-000393"
  tag "fix_id": "F-63391r1_fix"
  tag "cci": ["CCI-002754"]
  tag "nist": ["SI-10 (3)", "Rev_4"]
end
