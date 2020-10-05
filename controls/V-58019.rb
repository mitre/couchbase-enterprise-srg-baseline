# encoding: UTF-8

control "V-58019" do
  title "Couchbase must enforce discretionary access control policies, as
  defined by the data owner, over defined subjects and objects."
  desc  "Discretionary Access Control (DAC) is based on the notion that
  individual users are \"owners\" of objects and therefore have discretion over
  who should be authorized to access the object and in which mode (e.g., read or
  write). Ownership is usually acquired as a consequence of creating the object
  or via specified ownership assignment. DAC allows the owner to determine who
  will have access to objects they control. An example of DAC includes
  user-controlled table permissions.

  When discretionary access control policies are implemented, subjects are
  not constrained with regard to what actions they can take with information for
  which they have already been granted access. Thus, subjects that have been
  granted access to information are not prevented from passing (i.e., the
  subjects have the discretion to pass) the information to other subjects or
  objects.

  A subject that is constrained in its operation by Mandatory Access Control
  policies is still able to operate under the less rigorous constraints of this
  requirement. Thus, while Mandatory Access Control imposes constraints
  preventing a subject from passing information to another subject operating at a
  different sensitivity level, this requirement permits the subject to pass the
  information to any subject at the same sensitivity level.

  The policy is bounded by the information system boundary. Once the
  information is passed outside of the control of the information system,
  additional means may be required to ensure the constraints remain in effect.
  While the older, more traditional definitions of discretionary access control
  require identity-based access control, that limitation is not required for this
  use of discretionary access control.
  "
  desc  "check", "
  Review system documentation to identify the required discretionary access
  control (DAC).
      
  Review the security configuration of the database and Couchbase. If
  applicable, review the security configuration of the application(s) using the
  database.
  If the discretionary access control defined in the documentation is not
  implemented in the security configuration, this is a finding.
      
  Review Couchbase functionality considered privileged in the context of the
  system in question.
  $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
  --list
  If any functionality considered privileged has access privileges granted to
  non-privileged users, this is a finding.
  "
  desc  "fix", "Implement the organization's DAC policy in the security
  configuration of the database and Couchbase, and, if applicable, the security
  configuration of the application(s) using the database."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000328-DB-000301"
  tag "gid": "V-58019"
  tag "rid": "SV-72449r1_rule"
  tag "stig_id": "SRG-APP-000328-DB-000301"
  tag "fix_id": "F-63227r1_fix"
  tag "cci": ["CCI-002165"]
  tag "nist": ["AC-3 (4)", "Rev_4"]

  admin_users = []
  json_output = command("#{input('cb_bin_dir')}/couchbase-cli user-manage -u #{input('cb_full_admin')} \
  -p #{input('cb_full_admin_password')} --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
  --list | grep -B7 -A3 '\"role\": \"admin\"' | grep 'id'").stdout.split("\n")
  
  if json_output.empty?
    describe 'This test is skipped because there are no users found.' do
      skip 'This test is skipped because there are no users found.'
    end 
  else
    json_output.each do |output|
      user = command("echo '#{output}' | awk -F '\"' '{print $4}'").stdout.strip
      admin_users.push(user)
    end

    admin_users.each do |user|
      describe "Each admin user in the list should have the correct privileges. #{user}"  do
        subject { user }
        it { should be_in input('cb_admin_users').uniq.flatten }
      end
    end
  end 

  if file(input('cb_static_conf')).exist?
    describe file(input('cb_static_conf')) do
      its('owner') { should be_in input('cb_service_user') }
      its('group') { should be_in input('cb_service_group') }
      it { should_not be_more_permissive_than('0600') }
    end
  else
    describe 'This test is skipped because no static configuration was found.' do
      skip 'This test is skipped because no static configuration was found.'
    end 
  end
  
  if file(input('cb_audit_log')).exist?
    describe file(input('cb_audit_log')) do
      its('owner') { should be_in input('cb_service_user') }
      its('group') { should be_in input('cb_service_group') }
      it { should_not be_more_permissive_than('0600') }
    end
  else
    describe 'This test is skipped because no audit log was found.' do
      skip 'This test is skipped because no audit log was found.'
    end 
  end
end
