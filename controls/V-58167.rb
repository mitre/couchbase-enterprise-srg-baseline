# encoding: UTF-8
control "V-58167" do
  title "Couchbase must only accept end entity certificates issued by DoD PKI or
  DoD-approved PKI Certification Authorities (CAs) for the establishment of all
  encrypted sessions."
  desc  "Only DoD-approved external PKIs have been evaluated to ensure that
  they have security controls and identity vetting procedures in place which are
  sufficient for DoD systems to rely on the identity asserted in the certificate.
  PKIs lacking sufficient security controls and identity vetting procedures risk
  being compromised and issuing certificates that enable adversaries to
  impersonate legitimate users.
  
  The authoritative list of DoD-approved PKIs is published at
  http://iase.disa.mil/pki-pke/interoperability.
  
  This requirement focuses on communications protection for Couchbase session
  rather than for the network packet.
  "
  desc  "check", "
  Verify that certificate used is issued by a valid DoD certificate authority 
  using the following command:
   $ openssl x509 -in <path_to_certificate_pem_file> -text | grep -i \"issuer\").

  If there is any issuer present in the certificate that is not a DoD approved
  certificate authority, this is a finding
  "
  desc  "fix", "
  Revoke trust in any certificates not issued by a DoD-approved
  certificate authority. 
    $ openssl ca -revoke <cert-locationt>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000427-DB-000385"
  tag "gid": "V-58167"
  tag "rid": "SV-72597r1_rule"
  tag "stig_id": "SRG-APP-000427-DB-000385"
  tag "fix_id": "F-63375r3_fix"
  tag "cci": ["CCI-002470"]
  tag "nist": ["SC-23 (5)", "Rev_4"]

  describe 'The Couchbase ssl certificate issuer' do
    subject { command("openssl x509 -in #{input('cb_ca_file_path')} -text | grep -i 'issuer'").stdout }
    it { should include 'DoD' }
  end  

end
