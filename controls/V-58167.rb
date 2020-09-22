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
  If Couchbase will accept non-DoD approved PKI end-entity
  certificates, this is a finding.
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

  certificate_issuer = command("openssl x509 -in -text | grep -i 'issuer'").stdout.split("\n")
 
  describe "Couchbase's should have certificates with issuers." do
    subject {certificate_issuer}
    it { should_not eq [] }
  end

  certificate_issuer.each do |issuer|
    describe "The Couchbase certificate issuer should be DoD approved. #{issuer}" do
      subject {issuer}  
      it { should include 'DoD' }
    end
  end  
end
