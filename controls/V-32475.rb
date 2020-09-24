# encoding: UTF-8

control "V-32475" do
  title "Couchbase, when utilizing PKI-based authentication, must validate
  certificates by performing RFC 5280-compliant certification path validation."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.
  A certificates certification path is the path from the end entity certificate
  to a trusted root certification authority (CA).
  Certification path validation is necessary for a relying party to make an
  informed decision regarding acceptance of an end entity certificate.
  Certification path validation includes checks such as certificate issuer trust,
  time validity and revocation status for each certificate in the certification
  path.  Revocation status information for CA and subject certificates in a
  certification path is commonly provided via certificate revocation lists (CRLs)
  or online certificate status protocol (OCSP) responses.

  Database Management Systems that do not validate certificates by performing
  RFC 5280-compliant certification path validation are in danger of accepting
  certificates that are invalid and/or counterfeit. This could allow unauthorized
  access to the database.
  "
  desc  "check", "
  If Couchbase is not using PKI-based authentication, this check is Not
  Applicable (NA).

  If client authentication is enabled, then Couchbase automatically performs path 
  validation.
    
  As the Full Admin, verify that that path validating is being performed with
  the following command:
    $ couchbase-cli ssl-manage -c <host>:<port> -u <Full Admin> -p <Password> 
    --client-auth --extended

  Review the output. If \"state\" is not set to \"enabled\" or \"mandatory\", 
  this is a finding.
  "
  desc  "fix", "
  As the Full Admin, configure Couchbase to validate certificates by
  performing RFC 5280-compliant certification path validation with the following
  command:
    $ couchbase-cli ssl-manage -c <host>:<port> -u <Full Admin> -p <Password>
    --set-client-auth <Auth Config File>
    Example:
    {
      \"state\": \"enable\",
      \"prefixes\": [
        {
          \"path\": \"subject.cn\",
          \"prefix\": \"www.cb-\",
          \"delimiter\": \".\"
        }
      ]
    }
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000175-DB-000067"
  tag "gid": "V-32475"
  tag "rid": "SV-42812r3_rule"
  tag "stig_id": "SRG-APP-000175-DB-000067"
  tag "fix_id": "F-36390r3_fix"
  tag "cci": ["CCI-000185"]
  tag "nist": ["IA-5 (2) (a)", "Rev_4"]

  if input('cb_use_pki') == "true"
    describe.one do 

      describe json( command: "#{input('cb_bin_dir')}/couchbase-cli ssl-manage \
      -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
      -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')}  \
      --client-auth --extended") do
        its('state') { should eq "enabled" }
      end

      describe json( command: "#{input('cb_bin_dir')}/couchbase-cli ssl-manage \
      -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
      -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')}  \
      --client-auth --extended") do
        its('state') { should eq "mandatory" }
      end
      
    end 
  else
    impact 0.0
    describe "Couchbase is not using PKI-based authentication, 
    therefore this check is Not Applicable (NA)" do
      skip "Couchbase is not using PKI-based authentication, 
      therefore this check is Not Applicable (NA)"
    end
  end
end
