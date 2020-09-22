# encoding: UTF-8

control "V-58067" do
  title "Couchbase must provide the means for individuals in authorized roles
  to change the auditing to be performed on all application components, based on
  all selectable event criteria within organization-defined time thresholds."
  desc  "If authorized individuals do not have the ability to modify auditing
  parameters in response to a changing threat environment, the organization may
  not be able to effectively respond, and important forensic information may be
  lost.

  This requirement enables organizations to extend or limit auditing as
  necessary to meet organizational requirements. Auditing that is limited to
  conserve information system resources may be extended to address certain threat
  situations. In addition, auditing may be limited to a specific set of events to
  facilitate audit reduction, analysis, and reporting. Organizations can
  establish time thresholds in which audit actions are changed, for example, near
  real time, within minutes, or within hours.
  "
  desc  "check", "
  If Couchbase does not provide the ability for users in authorized roles to
  reconfigure auditing at any time of the user's choosing, this is a finding.
    
  If changes in audit configuration cannot take effect until after a certain
  time or date, or until some event, such as a server restart, has occurred, and
  if that time or event does not meet the requirements specified by the
  application owner, this is a finding.
  "
  desc  "fix", "
  Deploy a Couchbase database that provides the ability for users in
  authorized roles to reconfigure auditing at any time.
      
  Deploy a Couchbase that allows audit configuration changes to take effect
  within the timeframe required by the application owner and without involving
  actions or events that the application owner rules unacceptable.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000353-DB-000324"
  tag "gid": "V-58067"
  tag "rid": "SV-72497r1_rule"
  tag "stig_id": "SRG-APP-000353-DB-000324"
  tag "fix_id": "F-63275r1_fix"
  tag "cci": ["CCI-001914"]
  tag "nist": ["AU-12 (3)", "Rev_4"]

  describe "This test requires a Manual Review: Review Couchbase documentation to verify if it provides the ability for users in authorized roles to
  reconfigure auditing at any time of the user's choosing" do
    skip "This test requires a Manual Review: Review Couchbase documentation to verify if it provides the ability for users in authorized roles to
    reconfigure auditing at any time of the user's choosing" 
  end
end
