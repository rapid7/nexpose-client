# Nexpose-Client
[![Gem Version](https://badge.fury.io/rb/nexpose.svg)](http://badge.fury.io/rb/nexpose) [![Build Status](https://travis-ci.org/rapid7/nexpose-client.svg?branch=master)](https://travis-ci.org/rapid7/nexpose-client) [![Test Coverage](https://codeclimate.com/github/rapid7/nexpose-client/badges/coverage.svg)](https://codeclimate.com/github/rapid7/nexpose-client) [![Inline docs](http://inch-ci.org/github/rapid7/nexpose-client.svg?branch=master)](http://inch-ci.org/github/rapid7/nexpose-client) [![Code Climate](https://codeclimate.com/github/rapid7/nexpose-client/badges/gpa.svg)](https://codeclimate.com/github/rapid7/nexpose-client)

This is the official gem package for the Ruby Nexpose API.

For assistance with using the gem, to share your scripts, or to discuss different approaches, please visit the Rapid7 forums for Nexpose: https://community.rapid7.com/community/nexpose/nexpose-apis

Check out https://github.com/rapid7/nexpose-client/wiki for walk-throughs and release notes for recent versions.

This gem is heavily used for internal, automated testing of the Nexpose product. It provides calls to the Nexpose XML APIs version 1.1 and 1.2 (except for some multi-tenant operations). It also includes a number of helper methods which are not currently exposed through alternate means.


## Contributions

We welcome contributions to this package. Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

Our coding standards include:

* Favor returning classes over key-value maps. Classes tend to be easier for users to manipulate and use.
* Unless otherwise noted, code should adhere to the Ruby Style Guide: https://github.com/bbatsov/ruby-style-guide
* Use YARDoc comment style to improve the API documentation of the gem.

## License

The nexpose-client gem is provided under the 3-Clause BSD License. See [COPYING](COPYING) for details.
 
## Credits

Rapid7, Inc.
