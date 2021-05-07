# couchbase-enterprise-srg-baseline

InSpec Profile to validate the secure configuration of couchbase-enterprise-srg-baseline, against SRG Version 2 Release 10 InSpec profile for CouchBase Server Enterprise 6.x

## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __ssh__.

The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```yaml
# Couchbase is Running in Docker Environment - True/False
is_docker: ''

# Couchbase Service Account
cb_service_user: ''

# Couchbase Service Group
cb_service_group: ''

# Couchbase Full Admin Account
cb_full_admin: ''

# Couchbase Full Admin Password
cb_full_admin_password: ''

# Couchbase Cluster Host
cb_cluster_host: ''

# Couchbase Cluster Port
cb_cluster_port: ''

# Couchbase Cluster Query Port
cb_query_port: ''

# Couchbase Admin User Accounts
cb_admin_users: []

# Couchbase User Accounts
cb_users: []

# Couchbase Roles
cb_roles: []

# Path to Server Private Key File
cb_private_key_path: ''

# Path to Server CA File
cb_ca_file_path: ''

# Couchbase Latest Version
cb_latest_version: ''

# Couchbase Authentication Options - saslauthd
cb_use_saslauthd: ''

# Couchbase Authentication Options - LDAP
cb_use_ldap: ''

# Couchbase Authentication Options
cb_use_pki: ''

# Couchbase Domain - local/external
cb_auth_domain: ''

# Couchbase Unclassified Env - True/False
cb_unclassified_environment: ''

# Path to Couchbase Home Directory
cb_home_dir: ''

# Path to Couchbase Data Directory
cb_data_dir: ''

# Path to Couchbase Bin Directory
cb_bin_dir: ''

# Path to Couchbase Configuration Directory
cb_config_dir: ''

# Path to Couchbase Static Configuration File
cb_static_conf: ''

# Path to Couchbase Log Directory
cb_log_dir: ''

# Path to Couchbase Audit Log File
cb_audit_log: ''

# Path to Couchbase Bucket Samples Directory
cb_samples_dir: ''

# Couchbase Sample Buckets
sample_buckets: []

# Couchbase Audit Events
cb_required_audit_events: []

# Couchbase Audit Event IDs
cb_required_audit_event_ids: []

# Couchbase Approved Packages - Redhat
cb_redhat_approved_packages: []

# Couchbase Approved Packages - Debian
cb_debian_approved_packages: []

# Couchbase Approved TLS Protocol
approved_ssl_protocol: ''

# Couchbase Approved Ciphers
approved_ciphers: []

# Couchbase Audit Categories - True/False
cb_audit_categories_of_information: ''

# Couchbase Audit Access to Objects - True/False
cb_audit_access_to_objects: ''

# Couchbase Requires Encryption at Rest - True/False
cb_require_encryption_at_rest: ''

# Couchbase Requires Security Labeling - True/False
cb_require_security_labeling: ''

# Couchbase Uses Standard Ports - True/False
cb_use_standard_ports: ''
```

# Running This Baseline Directly from Github

```
# How to run
inspec exec https://github.com/mitre/couchbase-enterprise-srg-baseline/archive/master.tar.gz -t ssh:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/couchbase-enterprise-srg-baseline
inspec archive couchbase-enterprise-srg-baseline
inspec exec <name of generated archive> -t ssh:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd couchbase-enterprise-srg-baseline
git pull
cd ..
inspec archive couchbase-enterprise-srg-baseline --overwrite
inspec exec <name of generated archive> -t ssh:// --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

### Setup Environment

1. Clone the repo via `git clone git@github.com:mitre/couchbase-enterprise-srg-baseline.git`
2. cd to `couchbase-enterprise-srg-baseline`
3. Run `gem install bundler`
4. Run `bundle install`
5. Run `export KITCHEN_YAML=kitchen.vagrant.yml` - Docker and EC2 Kitchen Yaml files are available for testing

### Execute Tests

1. Run `bundle exec kitchen create` - create host based on two suites, vanilla and hardened
2. Run `bundle exec kitchen list` - you should see the following choices:
   - `hardened-rhel-7-couchbase-602-enterprise`
   - `vanilla-rhel-7-couchbase-602-enterprise`
   - `hardened-rhel-7-couchbase-660-enterprise`
   - `vanilla-rhel-7-couchbase-660-enterprise`
3. Run `bundle exec kitchen converge`
4. Run `bundle exec kitchen list` - your should see your hosts with status "converged"
5. Run `bundle exec kitchen verify` - Once finished, the results should be in the 'results' directory.

## Authors
* MITRE SAF Team

## Special Thanks 
* Mohamed El-Sharkawi - [HackerShark](https://github.com/HackerShark)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/couchbase-enterprise-srg-baseline/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.
