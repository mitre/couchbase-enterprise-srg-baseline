# encoding: UTF-8

control 'V-58109' do
  title "The DBMS must generate audit records when unsuccessful logons or
connection attempts occur."
  desc  "For completeness of forensic analysis, it is necessary to track failed
attempts to log on to the DBMS. While positive identification may not be
possible in a case of failed authentication, as much information as possible
about the incident must be captured."
  desc  'rationale', ''
  desc  'check', "Review the DBMS audit settings. If an audit record is not
generated each time a user (or other principal) attempts but fails to log on or
connect to the DBMS (including attempts where the user ID is invalid/unknown),
this is a finding."
  desc  'fix', "
    Configure DBMS audit settings to generate an audit record each time a user
(or other principal) attempts but fails to log on or connect to the DBMS.

    Include attempts where the user ID is invalid/unknown. Ensure that the
audit record contains the time of the event and the user ID that was entered
(if any).
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag gid: 'V-58109'
  tag rid: 'SV-72539r1_rule'
  tag stig_id: 'SRG-APP-000503-DB-000351'
  tag fix_id: 'F-63317r1_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

