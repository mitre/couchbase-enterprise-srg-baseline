# encoding: UTF-8

control "V-32398" do
  title "Couchbase must protect its audit configuration from unauthorized
modification."
  desc  "Protecting audit data also includes identifying and protecting the
tools used to view and manipulate log data. Therefore, protecting audit tools
is necessary to prevent unauthorized operation on audit data.

    Applications providing tools to interface with audit data will leverage
user permissions and roles identifying the user accessing the tools and the
corresponding rights the user enjoys in order make access decisions regarding
the modification of audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.
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
      $ sudo chown -R couchbase:couchbase
/opt/couchbase/etc/couchbase/static_config
      $ sudo chmod 600 /opt/couchbase/etc/couchbase/static_config
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000122-DB-000203"
  tag "gid": "V-32398"
  tag "rid": "SV-42735r3_rule"
  tag "stig_id": "SRG-APP-000122-DB-000203"
  tag "fix_id": "F-36312r2_fix"
  tag "cci": ["CCI-001494"]
  tag "nist": ["AU-9", "Rev_4"]


  admin_users = []
  json_output = command("couchbase-cli user-manage -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
  --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} --list | grep -B7 -A3 '\"role\": \"admin\"' | grep 'id'").stdout.split("\n")
  
  json_output.each do |output|
    user = command("echo '#{output}' | awk -F '\"' '{print $4}'").stdout.strip
    admin_users.push(user)
  end

  admin_users.each do |user|
    describe "Each admin user in the list should be documented. #{user}" do
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
