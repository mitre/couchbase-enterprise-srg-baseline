# encoding: UTF-8
control "V-58059" do
  desc  "rationale", ""
  desc  "check", "
    As the Full Admin, log into the cluster to and use the following
documentation to review email alert settings (based on version) or use the
corresponding curl request:
    Couchbase Server 6.0:
https://docs.couchbase.com/server/6.0/manage/manage-settings/configure-alerts.html
    curl -u <Admin>:<Admin Password> http://10.5.2.54:8091/settings/alerts
    Couchbase Server 6.5
https://docs.couchbase.com/server/6.5/manage/manage-settings/configure-alerts.html
    curl -u <Admin>:<Password> http://[localhost]:8091/settings/alerts
    Couchbase Server 6.6
https://docs.couchbase.com/server/6.6/manage/manage-settings/configure-alerts.html
    curl -u <Admin>:<Password> http://[localhost]:8091/settings/alerts
    Verify that email alerts are being sent to the correct recipients and that
the following options have been enabled:
      - \"enabled\" set to true
      - \"--alert-audit-msg-dropped\"
      - \"--alert-disk-space\"
    If the email alerts are not enabled, this is a finding. If the email alerts
are enabled, but do not have the \"--alert-audit-msg-dropped\" and
\"--alert-disk-space\" options set, this is a finding.
  "
  desc  "fix", "
    Execute the following command to enable alert to support staff for audit
log failures:
      $ couchbase-cli setting-alert --cluster <host>:<port> --u <Full Admin>
--password <Password> --enable-email-alert 1 --email-user <user>
--email-password <password> --email-host <email> --email-port <port>
--email-recipients <recipients>  --email-sender noreply@couchbase.com
--alert-audit-msg-dropped --alert-disk-space
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000360-DB-000320"
  tag "gid": "V-58059"
  tag "rid": "SV-72489r2_rule"
  tag "stig_id": "SRG-APP-000360-DB-000320"
  tag "fix_id": "F-63267r2_fix"
  tag "cci": ["CCI-001858"]
  tag "nist": ["AU-5 (2)", "Rev_4"]
end
