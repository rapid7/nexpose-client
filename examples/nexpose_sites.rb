#!/usr/bin/env ruby
require 'rubygems'
require 'nexpose'

require 'pp'

#
# Change these to point to your instance/user/password
#
host = "127.0.0.1"
port = "3790"
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
# Query a list of all NeXpose sites and display them
#
sites = @nsc.site_listing || []
case sites.length
when 0
	puts("There are currently no active sites on this NeXpose instance")
end

sites.each do |site|
	puts("    Site ##{site[:site_id]} '#{site[:name]}' Risk Factor: #{site[:risk_factor]} Risk Score: #{site[:risk_score]}")
end
