#!/usr/bin/env ruby
require 'rubygems'
require 'nexpose'

require 'pp'

#
# Change these to point to your instance/user/password
#
host = "127.0.0.1"
port = "3780"
user = "nxadmin"
pass = "nxadmin"

#
# Connect and authenticate
#
begin

	# Create a connection to the NeXpose instance
	@nsc = Nexpose::Connection.new(host, user, pass, port)

	# Authenticate to this instance (throws an exception if this fails)
	@nsc.login
	
rescue ::Nexpose::APIError => e
	$stderr.puts ("Connection failed: #{e.reason}")
	exit(1)
end

#
# Query the version through the NeXpose console interface
#
res = @nsc.console_command("ver")
pp res
