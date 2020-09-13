# encoding: UTF-8

control "V-32536" do
  title "Couchbase must isolate security functions from non-security functions."
  desc  "An isolation boundary provides access control and protects the
integrity of the hardware, software, and firmware that perform security
functions.

    Security functions are the hardware, software, and/or firmware of the
information system responsible for enforcing the system security policy and
supporting the isolation of code and data on which the protection is based.

    Developers and implementers can increase the assurance in security
functions by employing well-defined security policy models; structured,
disciplined, and rigorous hardware and software development techniques; and
sound system/security engineering principles.

    Database Management Systems typically separate security functionality from
non-security functionality via separate databases or schemas. Database objects
or code implementing security functionality should not be commingled with
objects or code implementing application logic. When security and non-security
functionality are commingled, users who have access to non-security
functionality may be able to access security functionality.
  "
  desc  "check", "
    Check Couchbase settings to determine whether objects or code implementing
security functionality are located in a separate security domain, such as a
separate database or schema created specifically for security functionality.
    If security-related database objects or code are not kept separate, this is
a finding.
  "
  desc  "fix", "Locate security-related database objects and code in a separate
database, schema, or other separate security domain from database objects and
code implementing application logic."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000233-DB-000124"
  tag "gid": "V-32536"
  tag "rid": "SV-42873r3_rule"
  tag "stig_id": "SRG-APP-000233-DB-000124"
  tag "fix_id": "F-36451r2_fix"
  tag "cci": ["CCI-001084"]
  tag "nist": ["SC-3", "Rev_4"]

  describe "This test requires a Manual Review: Check Couchbase settings to determine whether objects or code implementing
  security functionality are located in a separate security domain." do
    skip "This test requires a Manual Review: Check Couchbase settings to determine whether objects or code implementing
    security functionality are located in a separate security domain."
  end
end
