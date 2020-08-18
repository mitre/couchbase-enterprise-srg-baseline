# encoding: UTF-8

control 'V-32365' do
  title 'The DBMS must initiate session auditing upon startup.'
  desc  "Session auditing is for use when a user's activities are under
investigation. To be sure of capturing all activity during those periods when
session auditing is in use, it needs to be in operation for the whole time the
DBMS is running."
  desc  'rationale', ''
  desc  'check', "
    Review DBMS vendor documentation to determine whether the DBMS software is
capable of session auditing.

    If the DBMS is not capable of session auditing and a third party product is
not being used for session level auditing, this is a finding.

    If the DBMS is capable of session level auditing and specific session
audits are currently defined but session auditing is not enabled; or if a
third-party product is available for session auditing and specific session
audits are currently defined but session auditing is not enabled, this is a
finding.
  "
  desc  'fix', "
    Deploy a DBMS capable of session auditing.

    Configure the DBMS software or third-party product to enable session
auditing.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag gid: 'V-32365'
  tag rid: 'SV-42702r2_rule'
  tag stig_id: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-36280r3_fix'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end

