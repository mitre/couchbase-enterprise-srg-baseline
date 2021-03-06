# encoding: UTF-8

control "V-58021" do
  title "Execution of software modules (to include stored procedures,
  functions, and triggers) with elevated privileges must be restricted to
  necessary cases only."
  desc  "In certain situations, to provide required functionality, a Couchbase
  needs to execute internal logic (stored procedures, functions, triggers, etc.)
  and/or external code modules with elevated privileges. However, if the
  privileges required for execution are at a higher level than the privileges
  assigned to organizational users invoking the functionality
  applications/programs, those users are indirectly provided with greater
  privileges than assigned by organizations.

  Privilege elevation must be utilized only where necessary and protected
  from misuse.

  This calls for inspection of application source code, which will require
  collaboration with the application developers. It is recognized that in many
  cases, the database administrator (DBA) is organizationally separate from the
  application developers, and may have limited, if any, access to source code.
  Nevertheless, protections of this type are so important to the secure operation
  of databases that they must not be ignored. At a minimum, the DBA must attempt
  to obtain assurances from the development organization that this issue has been
  addressed, and must document what has been discovered.
  "
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

  describe "This test requires a Manual Review: Review the system documentation, database and Couchbase security
  configuration, source code for Couchbase internal logic, source code of external modules invoked by Couchbase , 
  and source code of the application(s) using the database." do
    skip "This test requires a Manual Review: Review the system documentation, database and Couchbase security
    configuration, source code for Couchbase internal logic, source code of external modules invoked by Couchbase , 
    and source code of the application(s) using the database."
  end
end
