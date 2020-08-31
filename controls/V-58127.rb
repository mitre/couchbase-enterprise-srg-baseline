# encoding: UTF-8

control "V-58127" do
  title "Couchbase must produce audit records of its enforcement of access
restrictions associated with changes to the configuration of Couchbase or
database(s)."
  desc  "Without auditing the enforcement of access restrictions against
changes to configuration, it would be difficult to identify attempted attacks
and an audit trail would not be available for forensic investigation for
after-the-fact actions.

    Enforcement actions are the methods or mechanisms used to prevent
unauthorized changes to configuration settings. Enforcement action methods may
be as simple as denying access to a file based on the application of file
permissions (access restriction). Audit items may consist of lists of actions
blocked by access restrictions or changes identified after the fact.
  "
  desc  "check", "
    Review Couchbase documentation to verify that audit records can be produced
when the system denies or fails to complete attempts to change the
configuration of Couchbase or database(s).
    If Couchbase is not capable of this, this is a finding.
    Review Couchbase/database security and audit configurations to verify that
audit records are produced when the system denies attempts to change the
configuration of Couchbase or database(s).
    If they are not produced, this is a finding.
    Review Couchbase/database security and audit configurations to verify that
audit records are produced when other errors prevent attempts to change the
configuration of Couchbase or database(s).
    If they are not produced, this is a finding.
  "
  desc  "fix", "
    Couchbase capable of producing the required audit records when it denies or
fails to complete attempts to change the configuration of Couchbase or
database(s).
    Configure Couchbase to produce audit records when it denies attempts to
change the configuration of Couchbase or database(s).
    Configure Couchbase to produce audit records when other errors prevent
attempts to change the configuration of Couchbase or database(s).
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000381-DB-000361"
  tag "gid": "V-58127"
  tag "rid": "SV-72557r1_rule"
  tag "stig_id": "SRG-APP-000381-DB-000361"
  tag "fix_id": "F-63335r1_fix"
  tag "cci": ["CCI-001814"]
  tag "nist": ["CM-5 (1)", "Rev_4"]
end
