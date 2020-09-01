# encoding: UTF-8

control "V-32192" do
  title "Couchbase must integrate with an organization-level
  authentication/access mechanism providing account management and automation for
  all users, groups, roles, and any other principals."
  desc  "Enterprise environments make account management for applications and
  databases challenging and complex. A manual process for account management
  functions adds the risk of a potential oversight or other error. Managing
  accounts for the same person in multiple places is inefficient and prone to
  problems with consistency and synchronization.

  A comprehensive application account management process that includes
  automation helps to ensure that accounts designated as requiring attention are
  consistently and promptly addressed.

  Examples include, but are not limited to, using automation to take action
  on multiple accounts designated as inactive, suspended, or terminated, or by
  disabling accounts located in non-centralized account stores, such as multiple
  servers. Account management functions can also include: assignment of group or
  role membership; identifying account type; specifying user access
  authorizations (i.e., privileges); account removal, update, or termination; and
  administrative alerts. The use of automated mechanisms can include, for
  example: using email or text messaging to notify account managers when users
  are terminated or transferred; using the information system to monitor account
  usage; and using automated telephone notification to report atypical system
  account usage.

  Couchbase must be configured to automatically utilize organization-level
  account management functions, and these functions must immediately enforce the
  organization's current account policy.

  Automation may be comprised of differing technologies that when placed
  together contain an overall mechanism supporting an organization's automated
  account management requirements.
  "
  desc  "check", "
  If all accounts are authenticated by the organization-level
  authentication/access mechanism and not by Couchbase, this is not a finding.
  
  If there are any accounts managed by Couchbase, review the system
  documentation for justification and approval of these accounts.

  As the Full Admin, list all RBAC users in each cluster with the following
  command:
    $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
    <host>:<port> --list

  If any Couchbase-managed accounts exist that are not documented and
  approved, this is a finding.
  "
  desc  "fix", "
  Integrate Couchbase security with an organization-level
  authentication/access mechanism providing account management for all users,
  groups, roles, and any other principals.
  For each Couchbase-managed account that is not documented and approved,
  either transfer it to management by the external mechanism, or document the
  need for it and obtain approval, as appropriate.
  
  To remove undocumented accounts, execute the following command:
    $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
    <host>:<port> --set --delete --rbac-username <username> --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000023-DB-000001"
  tag "gid": "V-32192"
  tag "rid": "SV-42509r3_rule"
  tag "stig_id": "SRG-APP-000023-DB-000001"
  tag "fix_id": "F-36116r2_fix"
  tag "cci": ["CCI-000015"]
  tag "nist": ["AC-2 (1)", "Rev_4"]

  if input('cb_auth_method') != "saslauthd"
    impact 0.0
    describe "All accounts are authenticated by the organization-level authentication/access 
    mechanism and not by Couchbase, therefore this is not a finding." do
      skip "All accounts are authenticated by the organization-level authentication/access 
      mechanism and not by Couchbase, therefore this is not a finding."
    end
  else
    rbac_accounts = input('cb_admin_users').clone << input('cb_users')
    user_accounts = []
    json_output = command("couchbase-cli user-manage -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} --list | grep 'id'").stdout.split("\n")
    json_output.each do |output|
      user_id = command("echo '#{output}' | awk -F '\"' '{print $4}'").stdout.strip
      user_accounts.push(user_id)
    end
    user_accounts.each do |user|
      describe 'Each user in the list' do
        subject { user }
        it { should be_in rbac_accounts.uniq.flatten }
      end
    end
  end 
end
