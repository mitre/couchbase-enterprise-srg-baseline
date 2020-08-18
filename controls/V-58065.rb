# encoding: UTF-8

control 'V-58065' do
  title "The DBMS must generate time stamps, for audit records and application
data, with a minimum granularity of one second."
  desc  "Without sufficient granularity of time stamps, it is not possible to
adequately determine the chronological order of records.

    Time stamps generated by the DBMS must include date and time. Granularity
of time measurements refers to the precision available in time stamp values.
Granularity coarser than one second is not sufficient for audit trail purposes.
Time stamp values are typically presented with three or more decimal places of
seconds; however, the actual granularity may be coarser than the apparent
precision. For example, SQL Server's GETDATE()/CURRENT_TMESTAMP values are
presented to three decimal places, but the granularity is not one millisecond:
it is about 1/300 of a second.

    Some DBMS products offer a data type called TIMESTAMP that is not a
representation of date and time. Rather, it is a database state counter and
does not correspond to calendar and clock time. This requirement does not refer
to that meaning of TIMESTAMP.
  "
  desc  'rationale', ''
  desc  'check', "
    Review product documentation to verify that the DBMS can generate time
stamps with a granularity of one second or finer. If it cannot, this is a
finding.

    Review audit log records produced by the DBMS for confirmation that time
stamps are recorded to a precision of one second or finer. If not, this is a
finding.

    Review time stamp values in audit trail columns/fields in application data
in the database. If the time stamps are not recorded to a precision of one
second or finer, this is a finding.
  "
  desc  'fix', "
    Deploy a DBMS that can generate and record time stamps with a granularity
of one second or finer.

    Configure auditing so that the time stamps are recorded to a precision of
one second or finer.

    Modify applications and/or column/field definitions so that the time stamps
in audit trail columns/fields in application data are recorded to a precision
of one second or finer.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000375-DB-000323'
  tag gid: 'V-58065'
  tag rid: 'SV-72495r1_rule'
  tag stig_id: 'SRG-APP-000375-DB-000323'
  tag fix_id: 'F-63273r1_fix'
  tag cci: ['CCI-001889']
  tag nist: ['AU-8 b']
end

