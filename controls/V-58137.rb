# encoding: UTF-8

control 'V-58137' do
  title "The DBMS must prohibit the use of cached authenticators after an
organization-defined time period."
  desc  "If cached authentication information is out-of-date, the validity of
the authentication information may be questionable."
  desc  'rationale', ''
  desc  'check', "
    Review system settings to determine whether the organization-defined limit
for cached authentication is implemented.

    If it is not implemented, this is a finding.
  "
  desc  'fix', "Modify system settings to implement the organization-defined
limit on the lifetime of cached authenticators."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000400-DB-000367'
  tag gid: 'V-58137'
  tag rid: 'SV-72567r1_rule'
  tag stig_id: 'SRG-APP-000400-DB-000367'
  tag fix_id: 'F-63345r1_fix'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end

