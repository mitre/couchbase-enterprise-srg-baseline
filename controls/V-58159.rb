# encoding: UTF-8

control 'V-58159' do
  title "The DBMS must implement NIST FIPS 140-2 validated cryptographic
modules to provision digital signatures."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
of utilizing encryption to protect data. The application must implement
cryptographic modules adhering to the higher standards approved by the federal
government since this provides assurance they have been tested and validated.

    For detailed information, refer to NIST FIPS Publication 140-2, Security
Requirements For Cryptographic Modules. Note that the product's cryptographic
modules must be validated and certified by NIST as FIPS-compliant.
  "
  desc  'rationale', ''
  desc  'check', "If the DBMS does not employ NIST FIPS 140-2 validated
cryptographic modules to provision digital signatures, this is a finding."
  desc  'fix', "Implement NIST FIPS 140-2 validated cryptographic modules to
provision digital signatures."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000514-DB-000381'
  tag gid: 'V-58159'
  tag rid: 'SV-72589r1_rule'
  tag stig_id: 'SRG-APP-000514-DB-000381'
  tag fix_id: 'F-63367r2_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13']
end

