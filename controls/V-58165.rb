# encoding: UTF-8
input('cb_cluster_host')
input('cb_cluster_port')
input('cb_full_admin')
input('cb_full_admin_password')

control "V-58165" do
  title "Couchbase must maintain the authenticity of communications sessions by
  guarding against man-in-the-middle attacks that guess at Session ID values."
  desc  "One class of man-in-the-middle, or session hijacking, attack involves
  the adversary guessing at valid session identifiers based on patterns in
  identifiers already known.

  The preferred technique for thwarting guesses at Session IDs is the
  generation of unique session identifiers using a FIPS 140-2 approved random
  number generator.

  However, it is recognized that available Couchbase products do not all
  implement the preferred technique yet may have other protections against
  session hijacking. Therefore, other techniques are acceptable, provided they
  are demonstrated to be effective."
  desc  "check", "
  Verify Couchbase has SSL enabled:
    $ couchbase-cli ssl-manage -c <localhost>:<port> -u <Full Admin> -p
    <Password> --client-auth --extended
  If Couchbase does not have SSL enabled, this is a finding.
  Review Couchbase settings to determine whether protections against
  man-in-the-middle attacks that guess at session identifier values are enabled.
  If they are not, this is a finding.
  "
  desc  "fix", "
  To make authorization mandatory run the following command:
    $ couchbase-cli ssl-manage -c <localhost>:<port> -u <Full Admin> -p
    <Password> --set-client-auth mandatory
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000224-DB-000384"
  tag "gid": "V-58165"
  tag "rid": "SV-72595r1_rule"
  tag "stig_id": "SRG-APP-000224-DB-000384"
  tag "fix_id": "F-63373r1_fix"
  tag "cci": ["CCI-001188"]
  tag "nist": ["SC-23 (3)", "Rev_4"]

  describe json({ command "couchbase-cli ssl-manage -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --client-auth --extended"} ) do
    its('state') { should eq 'enable' }
  end
end
