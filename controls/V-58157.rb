# encoding: UTF-8

control "V-58157" do
  title "Couchbase must use NSA-approved cryptography to protect classified
  information in accordance with the data owners requirements."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
  of utilizing encryption to protect data. The application must implement
  cryptographic modules adhering to the higher standards approved by the federal
  government since this provides assurance they have been tested and validated.
  It is the responsibility of the data owner to assess the cryptography
  requirements in light of applicable federal laws, Executive Orders, directives,
  policies, regulations, and standards.
  NSA-approved cryptography for classified networks is hardware based. This
  requirement addresses the compatibility of a Couchbase with the encryption
  devices.
  "
  desc  "check", "
  If Couchbase is deployed in an unclassified environment, this is not
  applicable (NA).
  If Couchbase is not using NSA-approved cryptography to protect classified
  information in accordance with applicable federal laws, Executive Orders,
  directives, policies, regulations, and standards, this is a finding.
  Verify Couchbase has SSL enabled:
    $ couchbase-cli ssl-manage -c <host>:<port>-u Administrator -p password
      --client-auth --extended
  If the response does not show SSL is enabled, this is a finding.
  "
  desc  "fix", "
  Configure Couchbase and related system components to use NSA-approved
  cryptography to protect classified information in accordance with applicable
  federal laws, Executive Orders, directives, policies, regulations, and
  standards.
  Configure Couchbase to enforce SSL:
   $ couchbase-cli ssl-manage -c <host>:<port> -u <Full Admin> -p <Password>
    --set-client-auth <Config File>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000416-DB-000380"
  tag "gid": "V-58157"
  tag "rid": "SV-72587r1_rule"
  tag "stig_id": "SRG-APP-000416-DB-000380"
  tag "fix_id": "F-63365r1_fix"
  tag "cci": ["CCI-002450"]
  tag "nist": ["SC-13", "Rev_4"]

  describe json({ command "couchbase-cli ssl-manage -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --client-auth --extended"}) do
    its('state') { should eq 'enable' }
  end  
end
