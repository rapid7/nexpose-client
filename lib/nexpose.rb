#
# The Nexpose API
#
=begin

Copyright (C) 2009-2012, Rapid7 LLC
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
require 'nexpose/error'
require 'nexpose/util'
require 'nexpose/user'
require 'nexpose/api_request'
require 'nexpose/manage'
require 'nexpose/misc'
require 'nexpose/report'
require 'nexpose/scan'
require 'nexpose/scan_engine'
require 'nexpose/silo'
require 'nexpose/site'
require 'nexpose/ticket'
require 'nexpose/vuln'
require 'nexpose/creds'
require 'nexpose/connection'
require 'nexpose/role'
require 'nexpose/common'
require 'nexpose/group'

module Nexpose

  # TODO add
  def self.site_device_scan(connection, site_id, device_array, host_array, debug = false)

    request_xml = '<SiteDevicesScanRequest session-id="' + connection.session_id.to_s + '" site-id="' + site_id.to_s + '">'
    request_xml += '<Devices>'
    device_array.each do |d|
      request_xml += '<device id="' + d.to_s + '"/>'
    end
    request_xml += '</Devices>'
    request_xml += '<Hosts>'
    # The host array can only by single IP addresses for now. TODO: Expand to full API Spec.
    host_array.each do |h|
      request_xml += '<range from="' + h.to_s + '"/>'
    end
    request_xml += '</Hosts>'
    request_xml += '</SiteDevicesScanRequest>'

    r = connection.execute(request_xml)
    r.success ? {:engine_id => r.attributes['engine_id'], :scan_id => r.attributes['scan-id']} : nil
  end

  # ==== Description
  # Echos the last XML API request and response for the specified object.  (Useful for debugging)
  def self.printXML(object)
    puts "request" + object.request_xml.to_s
    puts "response is " + object.response_xml.to_s
  end
end
