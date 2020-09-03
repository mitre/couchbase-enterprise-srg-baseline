# encoding: UTF-8

control "V-32363" do
  title "Couchbase must allow only the ISSM (or individuals or roles appointed
  by the ISSM) to select which auditable events are to be audited."
  desc  "check", "
  Only a user with Full Admin role can change auditing controls.
  As the Full Admin, get a list of all RBAC users with the following command:
    $ couchbase-cli user-manage -c  <localhost>:<port>  -u <Full Admin> -p
    <Password> --list

  If any users have the \"admin\" role that should not, this is a finding.

  Additionally, the permissions of the config file should also be verified.
  This can be done by running the following command:
    $ ls -la /opt/couchbase/etc/couchbase/static_config
    
  Review the ownership and permissions. If anyone other than couchbase is the
  owner and group owner, this is a finding. If permissions are not set to 600,
  this is a finding.
  "
  desc  "fix", "
  Remove users who should not have Full Admin role. To manage the roles this
  can be done by running the following command (Note: Do not include the
  \"admin\" role in command):
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
    -p <Password> --set --rbac-username <user> --rbac-password <password> \\
    --rbac-name <name> --roles <roles> \\
    --auth-domain <domain>

  As the root or sudo user, assign the correct permissions to the config file
  fun the following commands:
    $ sudo chown -R couchbase:couchbase /opt/couchbase/etc/couchbase/static_config
    $ sudo chmod 600 /opt/couchbase/etc/couchbase/static_config
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000090-DB-000065"
  tag "gid": "V-32363"
  tag "rid": "SV-42700r3_rule"
  tag "stig_id": "SRG-APP-000090-DB-000065"
  tag "fix_id": "F-36278r2_fix"
  tag "cci": ["CCI-000171"]
  tag "nist": ["AU-12 b", "Rev_4"]

  admin_users = []
  json_output = command("couchbase-cli user-manage -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} --list | grep -B7 -A3 '\"role\": \"admin\"' | grep 'id'").stdout.split("\n")
  
  json_output.each do |output|
    user = command("echo '#{output}' | awk -F '\"' '{print $4}'").stdout.strip
    admin_users.push(user)
  end

  admin_users.each do |user|
    describe 'Each admin user in the list' do
      subject { user }
      it { should be_in input('cb_admin_users').uniq.flatten }
    end
  end

  describe file(input('cb_static_conf')) do
    its('owner') { should be_in input('cb_service_user') }
    its('group') { should be_in input('cb_service_group') }
    it { should_not be_more_permissive_than('0600') }
  end

end
