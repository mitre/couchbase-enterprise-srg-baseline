# encoding: UTF-8
control "V-58021" do
  desc  "rationale", ""
  desc  "check", "
    Review the system documentation, database and Couchbase security
configuration, source code for Couchbase internal logic, source code of
external modules invoked by Couchbase , and source code of the application(s)
using the database.
    If elevation of Couchbase privileges is not utilized, this is not a finding.
    If elevation of Couchbase privileges is utilized but not documented, this
is a finding.
    If elevation of Couchbase privileges is documented, but not implemented as
described in the documentation, this is a finding.
    If the privilege-elevation logic can be invoked in ways other than
intended, or in contexts other than intended, or by subjects/principals other
than intended, this is a finding.
  "
  desc  "fix", "
    Determine where, when, how, and by what principals/subjects elevated
privilege is needed.
    Modify the database and Couchbase security configuration, Couchbase
internal logic, external modules invoked by Couchbase , and the application(s)
using the database, to ensure privilege elevation is used only as required.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000342-DB-000302"
  tag "gid": "V-58021"
  tag "rid": "SV-72451r2_rule"
  tag "stig_id": "SRG-APP-000342-DB-000302"
  tag "fix_id": "F-63229r1_fix"
  tag "cci": ["CCI-002233"]
  tag "nist": ["AC-6 (8)", "Rev_4"]
end
