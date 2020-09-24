# encoding: UTF-8

control "V-58147" do
  title "Couchbase must require users to re-authenticate when
  organization-defined circumstances or situations require re-authentication."
  desc "The DoD standard for authentication of an interactive user is the
  presentation of a Common Access Card (CAC) or other physical token bearing a
  valid, current, DoD-issued Public Key Infrastructure (PKI) certificate, coupled
  with a Personal Identification Number (PIN) to be entered by the user at the
  beginning of each session and whenever re-authentication is required.

  Without re-authentication, users may access resources or perform tasks for
  which they do not have authorization.

  When applications provide the capability to change security roles or
  escalate the functional capability of the application, it is critical the user
  re-authenticate.

  In addition to the re-authentication requirements associated with session
  locks, organizations may require re-authentication of individuals and/or
  devices in other situations, including (but not limited to) the following
  circumstances:

    (i) When authenticators change;
    (ii) When roles change;
    (iii) When security categories of information systems change;
    (iv) When the execution of privileged functions occurs;
    (v) After a fixed period of time; or
    (vi) Periodically.

  Within the DoD, the minimum circumstances requiring re-authentication are
  privilege escalation and role changes.
  "
  desc "check", "
  Review the organization-defined circumstances or situations
  and determine all situations where a user must re-authenticate. If there are
  any of these organization-defined circumstances under which a user is not
  required to re-authenticate, this is a finding.
  "
  desc "fix", "
  Modify and/or configure Couchbase and related applications and
  tools so that users are always required to re-authenticate when the specified
  cases needing reauthorization occur.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000389-DB-000372"
  tag "gid": "V-58147"
  tag "rid": "SV-72577r1_rule"
  tag "stig_id": "SRG-APP-000389-DB-000372"
  tag "fix_id": "F-63355r1_fix"
  tag "cci": ["CCI-002038"]
  tag "nist": ["IA-11", "Rev_4"]
  
  describe "This test requires a Manual Review: Determine all situations where a user must re-authenticate
    to re-authenticate, if Couchbase does not force re-authentication, this is a finding" do
    skip "This test requires a Manual Review: Determine all situations where a user must re-authenticate
    to re-authenticate, if Couchbase does not force re-authentication, this is a finding"
  end

  describe "This test requires a Manual Review: Couchbase does not support changing roles or escalating 
  privileges without re-authenticating as a different account." do
    skip "This test requires a Manual Review: Couchbase does not support changing roles or escalating 
    privileges without re-authenticating as a different account."
  end    
end
