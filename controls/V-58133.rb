# encoding: UTF-8

control "V-58133" do
  title "Couchbase must disable network functions, ports, protocols, and
  services deemed by the organization to be nonsecure, in accord with the Ports,
  Protocols, and Services Management (PPSM) guidance."
  desc  "Use of nonsecure network functions, ports, protocols, and services
  exposes the system to avoidable threats.
  "
  desc  "check", "
  Review the network functions, ports, protocols, and services in the
  Couchbase config:
    $ vi /opt/couchbase/etc/couchbase/static_config
  If any protocol is prohibited by the PPSM guidance and is enabled, this is
  a finding.
  "
  desc  "fix", "
  Ensure Couchbase is capable of disabling a network function, port,
  protocol, or service prohibited by the PPSM guidance.
  Disable each prohibited network function, port, protocol, or service.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000383-DB-000364"
  tag "gid": "V-58133"
  tag "rid": "SV-72563r1_rule"
  tag "stig_id": "SRG-APP-000383-DB-000364"
  tag "fix_id": "F-63341r1_fix"
  tag "cci": ["CCI-001762"]
  tag "nist": ["CM-7 (1) (b)", "Rev_4"]

  describe command("cat /opt/couchbase/etc/couchbase/static_config | grep \"port\"") do
    its('stdout') { should include input('cb_cluster_port') }
  end  

  if virtualization.system == 'docker'
  describe "This test requires a Manual Review: The docker container must have networking tools 
  to check its ports and their processes" do
	  skip "This test requires a Manual Review: The docker container must have networking tools 
    to check its ports and their processes"
	end

  else
    describe port(input('cb_cluster_port')) do
      it { should be_listening }
      its('processes') { should include 'couchbase' }
    end
  end
end
