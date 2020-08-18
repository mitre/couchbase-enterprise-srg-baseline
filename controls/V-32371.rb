# encoding: UTF-8

control 'V-32371' do
  title "The DBMS must produce audit records containing sufficient information
to establish the sources (origins) of the events."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Without establishing the source of the event, it is
impossible to establish, correlate, and investigate the events relating to an
incident.

    In order to compile an accurate risk assessment and provide forensic
analysis, it is essential for security personnel to know where events occurred,
such as application components, modules, session identifiers, filenames, host
names, and functionality.

    In addition to logging where events occur within the application, the
application must also produce audit records that identify the application
itself as the source of the event.

    Associating information about the source of the event within the
application provides a means of investigating an attack; recognizing resource
utilization or capacity thresholds; or identifying an improperly configured
application.
  "
  desc  'rationale', ''
  desc  'check', "
    Check DBMS settings and existing audit records to verify information
specific to the source (origin) of the event is being captured and stored with
audit records.

    If audit records exist without information regarding the source of the
event, this is a finding.
  "
  desc  'fix', "Configure DBMS audit settings to include the source of the
event as part of the audit record."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000098-DB-000042'
  tag gid: 'V-32371'
  tag rid: 'SV-42708r3_rule'
  tag stig_id: 'SRG-APP-000098-DB-000042'
  tag fix_id: 'F-36286r3_fix'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3']
end

