# encoding: UTF-8

control 'V-58077' do
  title "The DBMS must generate audit records when unsuccessful attempts to
modify privileges/permissions occur."
  desc  "Failed attempts to change the permissions, privileges, and roles
granted to users and roles must be tracked. Without an audit trail,
unauthorized attempts to elevate or restrict privileges could go undetected.

    In an SQL environment, modifying permissions is typically done via the
GRANT, REVOKE, and DENY commands.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.
  "
  desc  'rationale', ''
  desc  'check', "
    If there is no distinction in the DBMS's security architecture between
modifying permissions on the one hand, and adding and deleting permissions on
the other hand, this is not a finding.

    Review DBMS documentation to verify that audit records can be produced when
the system denies or fails to complete attempts to modify
privileges/permissions/role membership.

    If the DBMS is not capable of this, this is a finding.

    Review the DBMS/database security and audit configurations to verify that
audit records are produced when the system denies attempts to modify
privileges/permissions/role membership.

    If they are not produced, this is a finding.

    Review the DBMS/database security and audit configurations to verify that
audit records are produced when other errors prevent attempts to modify
privileges/permissions/role membership.

    If they are not produced, this is a finding.
  "
  desc  'fix', "
    Deploy a DBMS capable of producing the required audit records when it
denies or fails to complete attempts to modify privileges/permissions/role
membership.

    Configure the DBMS to produce audit records when it denies attempts to
modify privileges/permissions/role membership.

    Configure the DBMS to produce audit records when other errors prevent
attempts to modify privileges/permissions/role membership.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000495-DB-000329'
  tag gid: 'V-58077'
  tag rid: 'SV-72507r2_rule'
  tag stig_id: 'SRG-APP-000495-DB-000329'
  tag fix_id: 'F-63285r1_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

