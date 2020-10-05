# encoding: UTF-8

control "V-32393" do
  title "The audit information produced by Couchbase must be protected from
  unauthorized read access."
  desc  "If audit data were to become compromised, then competent forensic
  analysis and discovery of the true source of potentially malicious system
  activity is difficult, if not impossible, to achieve. In addition, access to
  audit records provides information an attacker could potentially use to his or
  her advantage.

  To ensure the veracity of audit data, the information system and/or the
  application must protect audit information from any and all unauthorized
  access. This includes read, write, copy, etc.

  This requirement can be achieved through multiple methods which will depend
  upon system architecture and design. Some commonly employed methods include
  ensuring log files enjoy the proper file system permissions utilizing file
  system protections and limiting log data location.

  Additionally, applications with user interfaces to audit records should not
  allow for the unfettered manipulation of or access to those records via the
  application. If the application provides access to the audit data, the
  application becomes accountable for ensuring that audit information is
  protected from unauthorized access.

  Audit information includes all information (e.g., audit records, audit
  settings, and audit reports) needed to successfully audit information system
  activity.
  "
  desc  "check", "
  Review locations of audit logs, both internal to the database and database
  audit logs located at the operating system level.
  Review the ownership and permissions of the audit logs:
    $ ls -la /opt/couchbase/var/lib/couchbase/logs

  If the log files are not owned by both the \"couchbase\" user and group, this is a finding. 
  If the file permission are not 600, this is a finding.
  "
  desc  "fix", "
  Apply controls and modify permissions to protect database audit log data
  from unauthorized read access, whether stored in the database itself or at the
  OS level.

  As the root or sudo user, change the permissions/ownership of the logs
  using the following commands:
    $ chown -R couchbase:couchbase /opt/couchbase/var/lib/couchbase/logs
    $ chmod 700 /opt/couchbase/var/lib/couchbase/logs
    $ chmod 600 /opt/couchbase/var/lib/couchbase/*.logs
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000118-DB-000059"
  tag "gid": "V-32393"
  tag "rid": "SV-42730r3_rule"
  tag "stig_id": "SRG-APP-000118-DB-000059"
  tag "fix_id": "F-36308r2_fix"
  tag "cci": ["CCI-000162"]
  tag "nist": ["AU-9", "Rev_4"]

  if file(input('cb_log_dir')).exist?
    describe file(input('cb_log_dir')) do
      its('owner') { should be_in input('cb_service_user') }
      its('group') { should be_in input('cb_service_group') }
      it { should_not be_more_permissive_than('0700') }
    end
      
    log_files = command("ls -p #{input('cb_log_dir')} | grep -v '/'").stdout.split("\n")

    if log_files.empty?
      describe 'This control must be reviewed manually because no log files are found 
      at the location specified.' do
        skip 'This control must be reviewed manually because no log files are found 
        at the location specified.'
      end 
    else
      log_files.each do |file|
        describe file("#{input('cb_log_dir')}/#{file}") do
          its('owner') { should be_in input('cb_service_user') }
          its('group') { should be_in input('cb_service_group') }
          it { should_not be_more_permissive_than('0600') }
        end
      end
    end
  else
    describe 'This control must be reviewed manually because no log directory is found 
    at the location specified.' do
      skip 'This control must be reviewed manually because no log directory is found 
      at the location specified.'
    end 
  end
end
