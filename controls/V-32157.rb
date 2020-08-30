# encoding: UTF-8
control "V-32157" do
  desc  "rationale", ""
  desc  "check", "
    Determine whether the system documentation specifies limits on the number
of concurrent Couchbase sessions per account by type of user. If it does not,
assume a limit of 10 for database administrators and 2 for all other users.
    Review the concurrent-sessions settings in Couchbase and/or the
applications using it, and/or the system software supporting it.
    If Couchbase is capable of enforcing this restriction but is not configured
to do so, this is a finding. This holds even if the restriction is enforced by
applications or supporting software.
    If it is not technically feasible for Couchbase to enforce this
restriction, but the application(s) or supporting software are configured to do
so, this is not a finding.
    If it is not technically feasible for Couchbase to enforce this
restriction, and applications and supporting software are not so configured,
this is a finding.
    If the value for any type of user account is not set, this is a finding.
    If a value is set but is not equal to the value specified in the
documentation (or the default value defined in this check) for the type of
user, this is a finding.
  "
  desc  "fix", "
    If Couchbase is capable of enforcing this restriction, but is not
configured to do so, configure it to do so. (This may involve the development
of one or more triggers.)
    If it is not technically feasible for Couchbase to enforce this
restriction, and the application(s) and supporting software are not configured
to do so, configure them to do so.
    If the value for any type of user account is not set, determine the correct
value and set it.
    If a value is set but is not equal to the value specified for the type of
user, determine the correct value, set it, and update the documentation, as
appropriate.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000001-DB-000031"
  tag "gid": "V-32157"
  tag "rid": "SV-42474r3_rule"
  tag "stig_id": "SRG-APP-000001-DB-000031"
  tag "fix_id": "F-36081r2_fix"
  tag "cci": ["CCI-000054"]
  tag "nist": ["AC-10", "Rev_4"]
end
