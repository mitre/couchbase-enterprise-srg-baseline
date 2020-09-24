# encoding: UTF-8

control "V-32478" do
  title "Couchbase must map the PKI-authenticated identity to an associated
  user account."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.
  Once a PKI certificate has been validated, it must be mapped to a Couchbase
  user account for the authenticated identity to be meaningful to Couchbase and
  useful for authorization decisions."
  desc  "check", "
  If Couchbase is not using PKI-based authentication, this check is Not
  Applicable (NA).

  The cn (Common Name) attribute of the certificate will be compared to the requested 
  database user account, and if they match the login will be allowed.

  If client authentication is enabled, then Couchbase automatically performs path 
  validation based on the database user account. 
    
  As the Full Admin, verify that that path validating is being performed with
  the following command:
    $ couchbase-cli ssl-manage -c <host>:<port> -u <Full Admin> -p <Password> 
    --client-auth --extended

  If \"path\" does not exist or is not set to \"subject.cn\", this is a finding.
  "
  desc  "fix", "
  Configure the Couchbase to map the authenticated identity directly to the
  Couchbase user account.
    
  For information on configuring Couchbase to use SSL, see the following
  documentation https://docs.couchbase.com/server/current/manage/manage-security/manage-certificates.html
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000177-DB-000069"
  tag "gid": "V-32478"
  tag "rid": "SV-42815r3_rule"
  tag "stig_id": "SRG-APP-000177-DB-000069"
  tag "fix_id": "F-36392r2_fix"
  tag "cci": ["CCI-000187"]
  tag "nist": ["IA-5 (2) (c)", "Rev_4"]

  if input('cb_use_pki') == "true"
    describe "The path validation should be set to 'subject.cn'. The" do 
      subject { command("#{input('cb_bin_dir')}/couchbase-cli ssl-manage \
      -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
      -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')}  \
      --client-auth --extended") }
      its('stdout') { should match /subject.cn/ }
    end
  else
    impact 0.0
    describe "Couchbase is not using PKI-based authentication, h
    therefore this check is Not Applicable (NA)" do
      skip "Couchbase is not using PKI-based authentication, 
      therefore this check is Not Applicable (NA)"
    end
  end
end
