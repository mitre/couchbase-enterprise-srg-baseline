# encoding: UTF-8

control 'V-58087' do
  title "The DBMS must generate audit records when security objects are
modified."
  desc  "Changes in the database objects (tables, views, procedures, functions)
that record and control permissions, privileges, and roles granted to users and
roles must be tracked. Without an audit trail, unauthorized changes to the
security subsystem could go undetected. The database could be severely
compromised or rendered inoperative."
  desc  'rationale', ''
  desc  'check', "
    If the DBMS architecture makes it impossible for any user, even with the
highest privileges, to modify the structure and logic of its built-in security
objects, and if there are no additional, locally-defined security objects in
the database(s), this is not a finding.

    Review DBMS documentation to verify that audit records can be produced when
security objects are modified.

    If the DBMS is not capable of this, this is a finding.

    Review the DBMS/database security and audit configurations to verify that
audit records are produced when security objects are modified.

    If they are not produced, this is a finding.
  "
  desc  'fix', "
    Deploy a DBMS capable of producing the required audit records when security
objects, such as tables, views, procedures, and functions, are modified.

    Configure the DBMS to produce audit records when security objects, such as
tables, views, procedures, and functions, are modified.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000496-DB-000334'
  tag gid: 'V-58087'
  tag rid: 'SV-72517r1_rule'
  tag stig_id: 'SRG-APP-000496-DB-000334'
  tag fix_id: 'F-63295r1_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

