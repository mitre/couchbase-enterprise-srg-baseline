# encoding: UTF-8

control "V-32529" do
  title "In the event of a system failure, Couchbase must preserve any
  information necessary to determine cause of failure and any information
  necessary to return to operations with least disruption to mission processes."
  desc  "Failure to a known state can address safety or security in accordance
  with the mission/business needs of the organization.

  Failure to a known secure state helps prevent a loss of confidentiality,
  integrity, or availability in the event of a failure of the information system
  or a component of the system.

  Preserving information system state information helps to facilitate system
  restart and return to the operational mode of the organization with less
  disruption of mission/business processes.

  Since it is usually not possible to test this capability in a production
  environment, systems should either be validated in a testing environment or
  prior to installation. This requirement is usually a function of the design of
  the IDPS component. Compliance can be verified by acceptance/validation
  processes or vendor attestation.
  "
  desc  "check", "
  Check Couchbase settings to determine whether organization-defined system
  state information is being preserved in the event of a system failure.

  If organization-defined system state information is not being preserved,
  this is a finding.

  As the Full Admin, verify that failover is enabled:
  $ curl -v -X GET -u <Full Admin>:<Password>
  http://<host>:<port>/settings/auto-failover
  
  If auto failover is not enabled, this is a finding
  "
  desc  "fix", "
  Configure Couchbase settings to preserve any organization-defined system
  state information in the event of a system failure.
  Review the documentation for automatic failover to specify the settings for
  organization-defined use:
  https://docs.couchbase.com/server/current/cli/cbcli/couchbase-cli-setting
  autofailover.html
  Enable auto failover and add additional parameters based on organizational
  demands:
  couchbase-cli setting-autofailover -c <host>:<port> --u <Full Admin> --p
  <Password> --enable-auto-failover 1 <parameters> 
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000226-DB-000147"
  tag "gid": "V-32529"
  tag "rid": "SV-42866r3_rule"
  tag "stig_id": "SRG-APP-000226-DB-000147"
  tag "fix_id": "F-36444r2_fix"
  tag "cci": ["CCI-001665"]
  tag "nist": ["SC-24", "Rev_4"]
  
  describe json( command: "curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} http://#{input('cb_cluster_host')}:\
  #{input('cb_cluster_port')}/settings/autoFailover") do
    its('enabled') { should eq true }
  end 
end
