module Nexpose
	class APIRequest
		include XMLUtils

		attr_reader :http
		attr_reader :uri
		attr_reader :headers
		attr_reader :retry_count
		attr_reader :time_out
		attr_reader :pause

		attr_reader :req
		attr_reader :res
		attr_reader :sid
		attr_reader :success

		attr_reader :error
		attr_reader :trace

		attr_reader :raw_response
		attr_reader :raw_response_data

		#
		#
		#
		def initialize(req, url, api_version='1.1')
			@url = url
			@req = req
			@api_version = api_version
			@url = @url.sub('API_VERSION', @api_version)
			prepare_http_client
		end

		#
		#
		#
		def prepare_http_client
			@retry_count = 0
			@retry_count_max = 10
			@time_out = 30
			@pause = 2
			@uri = URI.parse(@url)
			@http = Net::HTTP.new(@uri.host, @uri.port)
			@http.use_ssl = true
			#
			# XXX: This is obviously a security issue, however, we handle this at the client level by forcing
			#      a confirmation when the nexpose host is not localhost. In a perfect world, we would present
			#      the server signature before accepting it, but this requires either a direct callback inside
			#      of this module back to whatever UI, or opens a race condition between accept and attempt.
			#
			@http.verify_mode = OpenSSL::SSL::VERIFY_NONE
			@headers = {'Content-Type' => 'text/xml'}
			@success = false
		end

		#
		#
		#
		def execute
			@conn_tries = 0

			begin
				prepare_http_client
				@raw_response = @http.post(@uri.path, @req, @headers)
				@raw_response_data = @raw_response.read_body
				@res = parse_xml(@raw_response_data)

				if (not @res.root)
					@error = "NeXpose service returned invalid XML"
					return @sid
				end

				@sid = attributes['session-id']

				if (attributes['success'] and attributes['success'].to_i == 1)
					@success = true
				elsif @api_version =~ /1.2/ and @res and (@res.get_elements '//Exception').count < 1
					@success = true
				else
					@success = false
					@res.elements.each('//Failure/Exception') do |s|
						s.elements.each('message') do |m|
							@error = m.text
						end
						s.elements.each('stacktrace') do |m|
							@trace = m.text
						end
					end
				end
				# This is a hack to handle corner cases where a heavily loaded NeXpose instance
				# drops our HTTP connection before processing. We try 5 times to establish a
				# connection in these situations. The actual exception occurs in the Ruby
				# http library, which is why we use such generic error classes.
			rescue ::ArgumentError, ::NoMethodError
				if @conn_tries < 5
					@conn_tries += 1
					retry
				end
			rescue ::Timeout::Error
				if @conn_tries < 5
					@conn_tries += 1
					retry
				end
				@error = "NeXpose host did not respond"
			rescue ::Errno::EHOSTUNREACH, ::Errno::ENETDOWN, ::Errno::ENETUNREACH, ::Errno::ENETRESET, ::Errno::EHOSTDOWN, ::Errno::EACCES, ::Errno::EINVAL, ::Errno::EADDRNOTAVAIL
				@error = "NeXpose host is unreachable"
				# Handle console-level interrupts
			rescue ::Interrupt
				@error = "received a user interrupt"
			rescue ::Errno::ECONNRESET, ::Errno::ECONNREFUSED, ::Errno::ENOTCONN, ::Errno::ECONNABORTED
				@error = "NeXpose service is not available"
			rescue ::REXML::ParseException
				@error = "NeXpose has not been properly licensed"
			end

			if !(@success or @error)
				@error = "NeXpose service returned an unrecognized response: #{@raw_response_data.inspect}"
			end

			@sid
		end

		#
		#
		#
		def attributes(*args)
			return if not @res.root
			@res.root.attributes(*args)
		end

		#
		#
		#
		def self.execute(url, req, api_version='1.1')
			obj = self.new(req, url, api_version)
			obj.execute
			if (not obj.success)
				raise APIError.new(obj, "Action failed: #{obj.error}")
			end
			obj
		end

	end
end