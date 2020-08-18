# encoding: UTF-8

control 'V-32475' do
  title "The DBMS, when utilizing PKI-based authentication, must validate
certificates by performing RFC 5280-compliant certification path validation."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.

    A certificate’s certification path is the path from the end entity
certificate to a trusted root certification authority (CA).  Certification path
validation is necessary for a relying party to make an informed decision
regarding acceptance of an end entity certificate.  Certification path
validation includes checks such as certificate issuer trust, time validity and
revocation status for each certificate in the certification path.  Revocation
status information for CA and subject certificates in a certification path is
commonly provided via certificate revocation lists (CRLs) or online certificate
status protocol (OCSP) responses.

    Database Management Systems that do not validate certificates by performing
RFC 5280-compliant certification path validation are in danger of accepting
certificates that are invalid and/or counterfeit. This could allow unauthorized
access to the database.
  "
  desc  'rationale', ''
  desc  'check', "
    Review DBMS configuration to verify that certificates being accepted by the
DBMS are validated by performing RFC 5280-compliant certification path
validation.

    If certificates are not being validated by performing RFC 5280-compliant
certification path validation, this is a finding.
  "
  desc  'fix', "Configure the DBMS to validate certificates by performing RFC
5280-compliant certification path validation."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000175-DB-000067'
  tag gid: 'V-32475'
  tag rid: 'SV-42812r3_rule'
  tag stig_id: 'SRG-APP-000175-DB-000067'
  tag fix_id: 'F-36390r3_fix'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (a)']
end

