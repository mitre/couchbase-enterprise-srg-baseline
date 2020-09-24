# encoding: UTF-8

control "V-32514" do
  title "Couchbase must separate user functionality (including user interface
  services) from database management functionality."
  desc  "Information system management functionality includes functions
  necessary to administer databases, network components, workstations, or servers
  and typically requires privileged user access.

  The separation of user functionality from information system management
  functionality is either physical or logical and is accomplished by using
  different computers, different central processing units, different instances of
  the operating system, different network addresses, combinations of these
  methods, or other methods, as appropriate.

  An example of this type of separation is observed in web administrative
  interfaces that use separate authentication methods for users of any other
  information system resources.

  This may include isolating the administrative interface on a different
  domain and with additional access controls.

  If administrative functionality or information regarding Couchbase
  management is presented on an interface available for users, information on
  Couchbase settings may be inadvertently made available to the user.
  "
  desc  "check", "
  Check Couchbase settings and vendor documentation to verify that
  administrative functionality is separate from user functionality.
  
  The Couchbase web console provides management functions while the standard 
  client-to-node service accepts user and application connections to serve data. 

  Verify that the web console is not disabled.

  As the Full Admin, verify that HTTPS access is not disabled with the
  following command:
   $ curl -v -X GET -u <Full Admin>:<Password>
    http://<host>:<port>/settings/security

  Review the output of the command. If \"disableUIOverHttps\" is set to
  \"true\", this is finding.
  "
  desc  "fix", "
  The web console is available by default, unless both \"disableUIOverHttp\"
  and \"disableUIOverHttps\" are both set to \"true\".
    
  If \"disableUIOverHttps\" is set to \"true\", as the Full Admin, change
  this value to \"false\" with the following command:
    $ curl -v -X POST -u <Full Admin>:<Password>
    http://<host>:<port>/settings/security -d disableUIOverHttps=false
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000211-DB-000122"
  tag "gid": "V-32514"
  tag "rid": "SV-42851r3_rule"
  tag "stig_id": "SRG-APP-000211-DB-000122"
  tag "fix_id": "F-36429r2_fix"
  tag "cci": ["CCI-001082"]
  tag "nist": ["SC-2", "Rev_4"]

  describe "The Couchbase Web Console should not be disabled. The security setting" do
    subject { json( command: "curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} \
    http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/security") }
    its('disableUIOverHttps') { should eq false }
  end 
end
