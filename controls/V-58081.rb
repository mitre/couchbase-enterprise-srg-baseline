# encoding: UTF-8

control 'V-58081' do
  title "The DBMS must generate audit records when unsuccessful attempts to
delete privileges/permissions occur."
  desc  "Failed attempts to change the permissions, privileges, and roles
granted to users and roles must be tracked. Without an audit trail,
unauthorized attempts to elevate or restrict privileges could go undetected.

    In an SQL environment, deleting permissions is typically done via the
REVOKE or DENY command.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.
  "
  desc  'rationale', ''
  desc  'check', "
    Review DBMS documentation to verify that audit records can be produced when
the system denies or fails to complete attempts remove, revoke, or deny
privileges/permissions/role membership to any user or role.

    If the DBMS is not capable of this, this is a finding.

    Review the DBMS/database security and audit configurations to verify that
audit records are produced when the system denies attempts to remove, revoke,
or deny privileges/permissions/role membership to any user or role.

    If they are not produced, this is a finding.

    Review the DBMS/database security and audit configurations to verify that
audit records are produced when other errors prevent attempts to remove,
revoke, or deny privileges/permissions/role membership to any user or role.

    If they are not produced, this is a finding.
  "
  desc  'fix', "
    Deploy a DBMS capable of producing the required audit records when it
denies or fails to complete attempts to remove, revoke, or deny
privileges/permissions/role membership to any user or role.

    Configure the DBMS to produce audit records when it denies attempts to
remove, revoke, or deny privileges/permissions/role membership to any user or
role.

    Configure the DBMS to produce audit records when other errors prevent
attempts to remove, revoke, or deny privileges/permissions/role membership to
any user or role.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000499-DB-000331'
  tag gid: 'V-58081'
  tag rid: 'SV-72511r2_rule'
  tag stig_id: 'SRG-APP-000499-DB-000331'
  tag fix_id: 'F-63289r1_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

