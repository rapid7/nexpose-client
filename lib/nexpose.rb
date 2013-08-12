#
# The Nexpose API
#
=begin

Copyright (C) 2009-2013, Rapid7 LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

    * Neither the name of Rapid7 LLC nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=end

#
# WARNING! This code makes an SSL connection to the Nexpose server, but does NOT
#          verify the certificate at this time. This can be a security issue if
#          an attacker is able to man-in-the-middle the connection between the
#          Metasploit console and the Nexpose server. In the common case of
#          running Nexpose and Metasploit on the same host, this is a low risk.
#

#
# WARNING! This code is still rough and going through substantive changes. While
#          you can build tools using this library today, keep in mind that
#          method names and parameters may change in the future.
#

require 'date'
require 'rexml/document'
require 'net/https'
require 'net/http'
require 'uri'
require 'rex/mime'
require 'ipaddr'
require 'json'
require 'nexpose/error'
require 'nexpose/util'
require 'nexpose/alert'
require 'nexpose/ajax'
require 'nexpose/api_request'
require 'nexpose/common'
require 'nexpose/creds'
require 'nexpose/data_table'
require 'nexpose/engine'
require 'nexpose/group'
require 'nexpose/manage'
require 'nexpose/misc'
require 'nexpose/pool'
require 'nexpose/report'
require 'nexpose/role'
require 'nexpose/scan'
require 'nexpose/silo'
require 'nexpose/site'
require 'nexpose/ticket'
require 'nexpose/user'
require 'nexpose/vuln'
require 'nexpose/connection'

module Nexpose

  # ==== Description
  # Echos the last XML API request and response for the specified object.  (Useful for debugging)
  def self.print_xml(object)
    puts 'request: ' + object.request_xml.to_s
    puts 'response: ' + object.response_xml.to_s
  end
end
