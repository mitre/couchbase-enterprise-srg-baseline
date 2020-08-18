# encoding: UTF-8

control 'V-32391' do
  title "The DBMS must use system clocks to generate time stamps for use in
audit records and application data."
  desc  "Internal system clocks are typically a feature of server hardware and
are maintained and used by the operating system. They are typically
synchronized with an authoritative time server at regular intervals.

    Without an internal system clock used as the reference for the time stored
on each event to provide a trusted common reference for the time, forensic
analysis would be impeded. Determining the correct time a particular event
occurred on a system is critical when conducting forensic analysis and
investigating system events.

    Time stamps generated by the internal system clock and used by the DBMS
shall include both date and time. The time may be expressed in Coordinated
Universal Time (UTC), a modern continuation of Greenwich Mean Time (GMT), or
local time with an offset from UTC.

    If time sources other than the system time are used for audit records, the
timeline of events can get skewed. This makes forensic analysis of the logs
much less reliable.
  "
  desc  'rationale', ''
  desc  'check', "
    Using product documentation, verify that the DBMS uses current time stamp
values obtained from or synchronized with the internal system clock used by the
operating system.

    If it is not able to, this is a finding.

    If it is able to but is configured so that it does not do so, this is a
finding.
  "
  desc  'fix', "
    Deploy a DBMS that can use time stamp values obtained from or synchronized
with the internal system clock used by the operating system.

    Configure the DBMS to use time stamp values obtained from or synchronized
with the internal system clock used by the operating system.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000116-DB-000057'
  tag gid: 'V-32391'
  tag rid: 'SV-42728r3_rule'
  tag stig_id: 'SRG-APP-000116-DB-000057'
  tag fix_id: 'F-36306r2_fix'
  tag cci: ['CCI-000159']
  tag nist: ['AU-8 a']
end

