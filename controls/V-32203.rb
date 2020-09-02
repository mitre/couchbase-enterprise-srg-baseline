# encoding: UTF-8

control "V-32203" do
  title "Couchbase must enforce approved authorizations for logical access to
information and system resources in accordance with applicable access control
policies."
  desc  "Authentication with a DoD-approved PKI certificate does not
necessarily imply authorization to access Couchbase.  To mitigate the risk of
unauthorized access to sensitive information by entities that have been issued
certificates by DoD-approved PKIs, all DoD systems, including databases, must
be properly configured to implement access control policies.

    Successful authentication must not automatically give an entity access to
an asset or security boundary. Authorization procedures and controls must be
implemented to ensure each authenticated entity also has a validated and
current authorization. Authorization is the process of determining whether an
entity, once authenticated, is permitted to access a specific asset.
Information systems use access control policies and enforcement mechanisms to
implement this requirement.

    Access control policies include identity-based policies, role-based
policies, and attribute-based policies. Access enforcement mechanisms include
access control lists, access control matrices, and cryptography. These policies
and mechanisms must be employed by the application to control access between
users (or processes acting on behalf of users) and objects (e.g., devices,
files, records, processes, programs, and domains) in the information system.

    This requirement is applicable to access control enforcement applications,
a category that includes database management systems.  If Couchbase does not
follow applicable policy when approving access, it may be in conflict with
networks or other applications in the information system. This may result in
users either gaining or being denied access inappropriately and in conflict
with applicable policy.
  "
  desc  "check", "
  Check Couchbase settings to determine whether users are restricted from
  accessing objects and data they are not authorized to access.
  
  As the Full Admin, list all RBAC users in each cluster with the following
  command:
    $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
    <host>:<port> --list
  
  Verify the roles for each user account. If any user account is assigned a
  role the exceed those documented, this is a finding.
  "
  desc  "fix", "
  Configure Couchbase settings and access controls to permit user access only
  to objects and data that the user is authorized to view or interact with, and
  to prevent access to all other objects and data.
  
  To update roles assigned to users, execute the following command:
    $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
    <host>:<port> --set --delete --rbac-username <username> --roles <roles_list>
    --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000033-DB-000084"
  tag "gid": "V-32203"
  tag "rid": "SV-42520r3_rule"
  tag "stig_id": "SRG-APP-000033-DB-000084"
  tag "fix_id": "F-36127r3_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]

  user_roles = []
  json_output = command("couchbase-cli user-manage -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} --list | grep '\"role\":'").stdout.split("\n")
  json_output.each do |output|
    role = command("echo '#{output}' | awk -F '\"' '{print $4}'").stdout.strip
    user_roles.push(role)
  end
  user_roles.each do |role|
    describe 'Each role in the list' do
      subject { role }
      it { should be_in input('cb_roles').uniq.flatten }
    end
  end
end
