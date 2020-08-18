# encoding: UTF-8

control 'V-58107' do
  title "The DBMS must generate audit records when successful logons or
connections occur."
  desc  "For completeness of forensic analysis, it is necessary to track
who/what (a user or other principal) logs on to the DBMS."
  desc  'rationale', ''
  desc  'check', "Review the DBMS audit settings. If an audit record is not
generated each time a user (or other principal) logs on or connects to the
DBMS, this is a finding."
  desc  'fix', "Configure DBMS audit settings to generate an audit record each
time a user (or other principal) logs on or connects to the DBMS. Ensure that
the audit record contains the time of the event, the user ID, and session
identifier."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag gid: 'V-58107'
  tag rid: 'SV-72537r1_rule'
  tag stig_id: 'SRG-APP-000503-DB-000350'
  tag fix_id: 'F-63315r1_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

