# encoding: UTF-8

control "V-32427" do
  title "Access to external executables must be disabled or restricted."
  desc  "If the system were to allow any user to make changes to software
libraries, then those changes might be implemented without undergoing the
appropriate testing and approvals that are part of a robust change management
process.



    Accordingly, only qualified and authorized individuals shall be allowed to
obtain access to information system components for purposes of initiating
changes, including upgrades and modifications.



    Unmanaged changes that occur to the database software libraries or
configuration can lead to unauthorized or compromised installations.
  "
  desc  "check", "
    Review the database for definitions of application executable objects
stored external to the database.
    Determine if there are methods to disable use or access, or to remove
definitions for external executable objects.
    Verify each application executable object listed is authorized by the ISSO.
If any are not, this is a finding.
  "
  desc  "fix", "Disable use of or remove any external application executable
object definitions that are not authorized."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000093"
  tag "gid": "V-32427"
  tag "rid": "SV-42764r3_rule"
  tag "stig_id": "SRG-APP-000141-DB-000093"
  tag "fix_id": "F-36341r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]
end
