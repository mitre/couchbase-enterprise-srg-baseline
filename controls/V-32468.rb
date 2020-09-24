# encoding: UTF-8

control "V-32468" do
  title "If passwords are used for authentication, Couchbase must store only
  hashed, salted representations of passwords."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.

  Authentication based on User ID and Password may be used only when it is
  not possible to employ a PKI certificate, and requires AO approval.

  In such cases, database passwords stored in clear text, using reversible
  encryption, or using unsalted hashes would be vulnerable to unauthorized
  disclosure. Database passwords must always be in the form of one-way, salted
  hashes when stored internally or externally to Couchbase.
  "
  desc  "check", "
  If Couchbase is not storing credentials locally, this check is Not Applicable (NA).
  
  If password authentication is used and Couchbase stores credentials locally,
  SCRAM-SHA1, SCRAM-SHA256, and SCRAM-SHA512,  authentication protocols are 
  available with saslauthd enabled.
  These protocols use one-way, salted hash functions for passwords as documented
  here:
  https://docs.couchbase.com/server/current/learn/security/authentication-overview.html
  
  As Full Admin, execute the following command to check if saslauthd is
  enabled:
    $ curl -X GET -u <Full Admin>:<Password> http://<host>:<port>/settings/saslauthdAuth
    
  If saslauthd it is not enabled, this is a finding.
  "
  desc  "fix", "
  As the Full Admin, enable saslauthd with the following command:
    $ couchbase-cli setting-saslauthd -c <host>:<port> --username <Full Admin> --password <Password> --enabled 1
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000171-DB-000074"
  tag "gid": "V-32468"
  tag "rid": "SV-42805r3_rule"
  tag "stig_id": "SRG-APP-000171-DB-000074"
  tag "fix_id": "F-36383r4_fix"
  tag "cci": ["CCI-000196"]
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]

  if input('cb_auth_domain') == "local"
    describe "The saslauthd setting" do  
      subject { json( command: "curl -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} \
      http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/saslauthdAuth") }
      its('enabled') { should eq true }
    end
  else 
    impact 0.0 
    describe "Couchbase is not storing credentials locally, therefore this check is Not Applicable (NA)" do
      skip "Couchbase is not storing credentials locally, therefore this check is Not Applicable (NA)"
    end
  end
end
