module Nexpose

	# === Description
	# Object that represents a connection to a Nexpose Security Console.
	#
	# === Examples
	#   # Create a new Nexpose Connection on the default port
	#   nsc = Connection.new("10.1.40.10","nxadmin","password")
	#
	#   # Login to NSC and Establish a Session ID
	#   nsc.login()
	#
	#   # Check Session ID
	#   if (nsc.session_id)
	#       puts "Login Successful"
	#   else
	#       puts "Login Failure"
	#   end
	#
	#   # //Logout
	#   logout_success = nsc.logout()
	#   if (! logout_success)
	#       puts "Logout Failure" + "<p>" + nsc.error_msg.to_s
	#   end
	#
	class Connection
		include XMLUtils
		include NexposeAPI

		# true if an error condition exists; false otherwise
		attr_reader :error
		# Error message string
		attr_reader :error_msg
		# The last XML request sent by this object
		attr_reader :request_xml
		# The last XML response received by this object
		attr_reader :response_xml
		# Session ID of this connection
		attr_reader :session_id
		# The hostname or IP Address of the NSC
		attr_reader :host
		# The port of the NSC (default is 3780)
		attr_reader :port
		# The username used to login to the NSC
		attr_reader :username
		# The password used to login to the NSC
		attr_reader :password
		# The URL for communication
		attr_reader :url

		# Constructor for Connection
		def initialize(ip, user, pass, port = 3780, silo_id = nil)
			@host = ip
			@port = port
			@username = user
			@password = pass
			@silo_id = silo_id
			@session_id = nil
			@error = false
			@url = "https://#{@host}:#{@port}/api/API_VERSION/xml"
		end

		# Establish a new connection and Session ID
		def login
			begin
				login_hash = {'sync-id' => 0, 'password' => @password, 'user-id' => @username}
				unless @silo_id.nil?
					login_hash['silo-id'] = @silo_id
				end
				r = execute(make_xml('LoginRequest', login_hash))
			rescue APIError
				raise AuthenticationFailed.new(r)
			end
			if (r.success)
				@session_id = r.sid
				true
			end
		end

		# Logout of the current connection
		def logout
			r = execute(make_xml('LogoutRequest', {'sync-id' => 0}))
			if (r.success)
				return true
			end
			raise APIError.new(r, 'Logout failed')
		end

		# Execute an API request
		def execute(xml, version = '1.1')
			@api_version = version
			APIRequest.execute(@url, xml.to_s, @api_version)
		end

		# Download a specific URL
		def download(url)
			uri = URI.parse(url)
			http = Net::HTTP.new(@host, @port)
			http.use_ssl = true
			http.verify_mode = OpenSSL::SSL::VERIFY_NONE # XXX: security issue
			headers = {'Cookie' => "nexposeCCSessionID=#{@session_id}"}
			resp = http.get(uri.path, headers)
			resp.body
		end
	end
end
