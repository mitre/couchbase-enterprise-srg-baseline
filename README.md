# Database SRG Version 2 Release 10 InSpec profile for CouchBase Server Enterprise 6.x

InSpec profile testing secure configuration of CouchBase Server Enterprise 6.x

## Description

This InSpec compliance profile is a collection of automated tests for secure configuration of CouchBase Server Enterprise 6.x. (6.0.2 and 6.6.0)

InSpec is an open-source run-time framework and rule language used to specify compliance, security, and policy requirements for testing any node in your infrastructure.

## Versioning and State of Development

This project uses the [Semantic Versioning Policy](https://semver.org/).

### Branches

The master branch contains the latest version of the software leading up to a new release. Other branches contain feature-specific updates.

### Tags

Tags indicate official releases of the project.

Please note 0.x releases are works in progress (WIP) and may change at any time.

## Requirements

- [ruby](https://www.ruby-lang.org/en/) version 2.6 or greater
- [InSpec](http://inspec.io/) version 4.x or greater
- Install via ruby gem: `gem install inspec`

## Usage

InSpec makes it easy to run tests wherever you need. More options
listed here: [InSpec cli](http://inspec.io/docs/reference/cli/)

### Run with remote profile:

You may choose to run the profile via a remote url, this has the
advantage of always being up to date. The disadvantage is you may wish
to modify controls, which is only possible when downloaded. Also, the
remote profile is unintuitive for passing in attributes, which modify
the default values of the profile.

```bash
inspec exec https://github.com/mitre/couchbase-enterprise-srg-baseline/archive/master.tar.gz
```

Another option is to download the profile then run it, this allows
you to edit specific instructions and view the profile code.

```bash
# Clone Inspec Profile
$ git clone https://github.com/mitre/couchbase-enterprise-srg-baseline.git

# Run profile locally (assuming you have not changed directories since cloning)
# This will display compliance level at the prompt, and generate a JSON file
# for export called output.json
$ inspec exec couchbase-enterprise-srg-baseline --reporter cli json:output.json

# Run profile with custom settings defined in inputs.yml against the target
# server example.com.
$ inspec exec couchbase-enterprise-srg-baseline -t example.com --user root --password=Pa55w0rd --input-file=inputs.yml --reporter cli json:output.json

# Run profile with: custom attributes, ssh keyed into a custom target, and sudo.
$ inspec exec couchbase-enterprise-srg-baseline -t ssh://user@hostname -i /path/to/key --sudo --input-file=inputs.yml --reporter cli json:output.json

# Run profile with: custom attributes and a Docker container target.
$ inspec exec couchbase-enterprise-srg-baseline -t docker://52a949b41213 --input-file=inputs.yml --reporter cli json:output.json
```

## Testing with Kitchen

### Dependencies

- Ruby 2.6.0 or later
- [Virtualbox](https://www.virtualbox.org)
- [Vagrant](https://www.vagrantup.com)
- [Docker](https://docs.docker.com)

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

## Contribution

Please feel free to submit a PR or Issue on the board. To get an idea of our style and best practices, please see our InSpec training at:

- https://mitre-inspec-developer.netlify.com/
- https://mitre-inspec-advanced-developer.netlify.com/

## Useful References

- <https://lonesysadmin.net/2017/08/10/fix-winrm-client-issues/>
- <https://www.hurryupandwait.io/blog/understanding-and-troubleshooting-winrm-connection-and-authentication-a-thrill-seekers-guide-to-adventure>

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.
