# encoding: UTF-8
control "V-32523" do
  desc  "rationale", ""
  desc  "check", "
    Review Couchbase settings and vendor documentation to verify user sessions
are terminated, and session identifiers invalidated, upon user logout. If they
are not, this is a finding.
    Review system documentation and organization policy to identify other
events that should result in session terminations.
    If other session termination events are defined, review Couchbase settings
to verify occurrences of these events would cause session termination,
invalidating the session identifiers.
    As the Full Admin, get the current security settings with the following
command:
    $ curl -v -X GET -u <Full Admin>:<Password>
http://<host>:<port>/settings/security
    Review the output of the command. If uiSessionTimeout does not have a
value, this is a finding.
  "
  desc  "fix", "
    Configure Couchbase settings to terminate sessions, invalidating their
session identifiers, upon the occurrence of any organization- or policy-defined
session termination event.
    As the Full Admin, configure session timeout:
    $ curl -X POST -u  <Full Admin>:<Password>\\
http://<host>:<port>/settings/security \\ -d \"uiSessionTimeout=600\"
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000220-DB-000149"
  tag "gid": "V-32523"
  tag "rid": "SV-42860r2_rule"
  tag "stig_id": "SRG-APP-000220-DB-000149"
  tag "fix_id": "F-36438r2_fix"
  tag "cci": ["CCI-001185"]
  tag "nist": ["SC-23 (1)", "Rev_4"]
end
