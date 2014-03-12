# Nexpose-Client

This is the official gem package for the Ruby Nexpose API.

For assistance with using the gem, to share your scripts, or to discuss different approaches, please visit the Rapid7 forums for Nexpose: https://community.rapid7.com/community/nexpose/nexpose-apis

Check out https://github.com/rapid7/nexpose-client/wiki for walk-throughs and release notes for recent versions.

This gem is heavily used for internal, automated testing of the Nexpose product. It provides calls to the Nexpose XML APIs version 1.1 and 1.2 (except for some multi-tenant operations). It also includes a number of helper methods which are not currently exposed through alternate means.


## Contributions

We welcome contributions to this package.

Our coding standards include:

* Favor returning classes over key-value maps. Classes tend to be easier for users to manipulate and use.
* Unless otherwise noted, code should adhere to the Ruby Style Guide: https://github.com/bbatsov/ruby-style-guide
* Use YARDoc comment style to improve the API documentation of the gem.

## License

The nexpose-client gem is provided under the 3-Clause BSD License. See [COPYING](COPYING) for details.
 
## Credits

Rapid7, Inc.
