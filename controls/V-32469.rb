# encoding: UTF-8

control "V-32469" do
  title "If passwords are used for authentication, the Couchbase must transmit
  only encrypted representations of passwords."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.

  Authentication based on User ID and Password may be used only when it is
  not possible to employ a PKI certificate, and requires AO approval.

  In such cases, passwords need to be protected at all times, and encryption
  is the standard method for protecting passwords during transmission.

  Couchbase passwords sent in clear text format across the network are
  vulnerable to discovery by unauthorized users. Disclosure of passwords may
  easily lead to unauthorized access to the database.
  "
  desc  "check", "
  Couchbase Server 6.0.x and earlier -
  As the Full Admin, verify that HTTP access is disabled with the following
  command:
    $ curl -v -X GET -u <Full Admin>:<Password> http://<host>:<port>/settings/security

  Review the output of the command. If \"disableUIOverHttp\" is not set to
  \"true\", this is a finding.

  Review configuration settings for encrypting passwords in transit across
  the network. If passwords are not encrypted, this is a finding.
  
  Couchbase Server Version 6.5.x and later -
  As the Full Admin, verify that TLS is configured with the approved
  protocols and cipher suites with the following command:
    $ curl -v -X GET -u <Full Admin>:<Password> http://<host>:<port>/settings/security
  
  Review the output of the command. If \"disableUIOverHttp\" is not set to
  \"true\", this is finding. If \"tlsMinVersion\" is not set to an approved
  version, this is a finding. If \"cipherSuites\" is empty or not set to approved
  cipher suites, this is a finding.
  "
  desc  "fix", "
  Ensure passwords remain encrypted from source to destination by configuring
  TLS.
  Couchbase Server 6.0.x and earlier -
  As the Full Admin, disable https access to the console with the following
  command:
    $ couchbase-cli setting-security -c <host>:<port> -u <Full Admin> -p
    <Password> --disable-http-ui 1
    
  Configure encryption for transmission of passwords across the network. If
  the database does not provide encryption for logon events natively, employ
  encryption at the OS or network level.
  
  Couchbase Server Version 6.5.x and later -
  As the Full Admin, configure TLS with the following command:
    $ couchbase-cli setting-security -c <host>:<port> -u <Full Admin> -p
    <Password> --set --disable-http-ui 1 --tls-min-version <TLS Version>
    --cipher-suites <Cipher Suites>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000172-DB-000075"
  tag "gid": "V-32469"
  tag "rid": "SV-42806r3_rule"
  tag "stig_id": "SRG-APP-000172-DB-000075"
  tag "fix_id": "F-36384r2_fix"
  tag "cci": ["CCI-000197"]
  tag "nist": ["IA-5 (1) (c)", "Rev_4"]

  couchbase_version = command('couchbase-server -v | egrep -o "([0-9]{1,}\.)+[0-9]{1,}"').stdout.strip

  if couchbase_version <= '6.0.2'
    describe "The security setting" do
      subject { json( command: "curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} \
      http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/security") }
      its('disableUIOverHttp') { should eq true }
    end 
    describe "This test requires a Manual Review: Review configuration settings for 
    encrypting passwords in transit across the network. If passwords are not encrypted, 
    this is a finding." do 
      skip "This test requires a Manual Review: Review configuration settings for 
      encrypting passwords in transit across the network. If passwords are not encrypted, 
      this is a finding."
    end 
  else
    describe "The security setting" do
      subject { json( command: "curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} \
      http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/security") }
      its('disableUIOverHttp') { should eq true }
    end 

    describe "The security setting" do
      subject { json( command: "curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} \
      http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/security") }
      its('tlsMinVersion') { should eq input('approved_ssl_protocol') }
    end 

    describe "The security setting" do
      subject { json( command: "curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} \
      http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/security") }
      its('cipherSuites') { should be_in input('approved_ciphers') }
    end 
  end 
end
