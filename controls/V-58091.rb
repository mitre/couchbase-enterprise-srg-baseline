# encoding: UTF-8

control 'V-58091' do
  title "The DBMS must generate audit records when security objects are
deleted."
  desc  "The removal of security objects from the database/DBMS would seriously
degrade a system's information assurance posture. If such an event occurs, it
must be logged."
  desc  'rationale', ''
  desc  'check', "
    If the DBMS architecture makes it impossible for any user, even with the
highest privileges, to drop its built-in security objects, and if there are no
additional, locally-defined security objects in the database(s), this is not a
finding.

    Review DBMS documentation to verify that audit records can be produced when
security objects are drop.

    If the DBMS is not capable of this, this is a finding.

    Review the DBMS/database security and audit configurations to verify that
audit records are produced when security objects are drop.

    If they are not produced, this is a finding.
  "
  desc  'fix', "
    Deploy a DBMS capable of producing the required audit records when security
objects are deleted.

    Configure the DBMS to produce audit records when security objects are
deleted.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000501-DB-000336'
  tag gid: 'V-58091'
  tag rid: 'SV-72521r1_rule'
  tag stig_id: 'SRG-APP-000501-DB-000336'
  tag fix_id: 'F-63299r1_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

