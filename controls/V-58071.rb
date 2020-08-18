# encoding: UTF-8

control 'V-58071' do
  title "The DBMS must generate audit records when privileges/permissions are
added."
  desc  "Changes in the permissions, privileges, and roles granted to users and
roles must be tracked. Without an audit trail, unauthorized elevation or
restriction of privileges could go undetected. Elevated privileges give users
access to information and functionality that they should not have; restricted
privileges wrongly deny access to authorized users.

    In an SQL environment, adding permissions is typically done via the GRANT
command, or, in the negative, the DENY command.
  "
  desc  'rationale', ''
  desc  'check', "
    Review DBMS documentation to verify that audit records can be produced when
privileges/permissions/role memberships are added.

    If the DBMS is not capable of this, this is a finding.

    Review the DBMS/database security and audit configurations to verify that
audit records are produced when privileges/permissions/role memberships are
added.

    If they are not produced, this is a finding.
  "
  desc  'fix', "
    Deploy a DBMS capable of producing the required audit records when
privileges/permissions/role memberships are added.

    Configure the DBMS to produce audit records when
privileges/permissions/role memberships are added.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000495-DB-000326'
  tag gid: 'V-58071'
  tag rid: 'SV-72501r2_rule'
  tag stig_id: 'SRG-APP-000495-DB-000326'
  tag fix_id: 'F-63279r1_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

