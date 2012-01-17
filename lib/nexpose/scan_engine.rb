module Nexpose

	# ==== Description
	# Object that represents a listing of all of the scan engines available on to an NSC.
	#
	class EngineListing
		# true if an error condition exists; false otherwise
		attr_reader :error
		# Error message string
		attr_reader :error_msg
		# The last XML request sent by this object
		attr_reader :request_xml
		# The last XML response received by this object
		attr_reader :response_xml
		# The NSC Connection associated with this object
		attr_reader :connection
		# Array containing (EngineSummary*)
		attr_reader :engines
		# The number of scan engines
		attr_reader :engine_count

		# Constructor
		# EngineListing (connection)
		def initialize(connection)
			@connection = connection
			@engines = []
			@engine_count = 0
			@error = false
			r = @connection.execute('<EngineListingRequest session-id="' + @connection.session_id + '"/>', '1.2')

			if (r.success)
				r.res.elements.each('EngineListingResponse/EngineSummary') do |v|
					@engines.push(EngineSummary.new(v.attributes['id'], v.attributes['name'], v.attributes['address'],
													v.attributes['port'], v.attributes['status']))
				end
			else
				@error = true
				@error_msg = 'EngineListingRequest Parse Error'
			end
			@engine_count = @engines.length
		end
	end

	# TODO
	class EngineActivity
		# true if an error condition exists; false otherwise
		attr_reader :error
		# Error message string
		attr_reader :error_msg
		# The last XML request sent by this object
		attr_reader :request_xml
		# The last XML response received by this object
		attr_reader :response_xml
		# The NSC Connection associated with this object
		attr_reader :connection
		# The Engine ID
		attr_reader :engine_id
		# Array containing (ScanSummary*)
		attr_reader :scan_summaries
	end

	# ==== Description
	# Object that represents the summary of a scan engine.
	#
	# ==== Examples
	#
	#   # Create a new Nexpose Connection on the default port and Login
	#   nsc = Connection.new("10.1.40.10","nxadmin","password")
	#   nsc.login()
	#
	#   # Get the engine listing for the connection
	#   enginelisting = EngineListing.new(nsc)
	#
	#   # Print out the status of the first scan engine
	#   puts enginelisting.engines[0].status
	#
	class EngineSummary
		# A unique ID that identifies this scan engine
		attr_reader :id
		# The name of this scan engine
		attr_reader :name
		# The hostname or IP address of the engine
		attr_reader :address
		# The port there the engine is listening
		attr_reader :port
		# The engine status (active|pending-auth| incompatible|not-responding|unknown)
		attr_reader :status

		# Constructor
		# EngineSummary(id, name, address, port, status)
		def initialize(id, name, address, port, status)
			@id = id
			@name = name
			@address = address
			@port = port
			@status = status
		end

	end

	#-------------------------------------------------------------------------------------------------------------------
	#
	#-------------------------------------------------------------------------------------------------------------------
	class EngineConfig
		attr_accessor :id
		attr_accessor :address
		attr_accessor :name
		attr_accessor :port
		attr_accessor :scope
		attr_accessor :sites
		attr_accessor :priority

		def initialize(connection, engine_id)
			@connection = connection
			@id = nil
			@address = nil
			@name = nil
			@port = nil
			@scope = nil
			@priority = 'global'
			@sites = []

			r = @connection.execute('<EngineConfigRequest session-id="' + @connection.session_id + '" engine-id="' + engine_id + '"/>', '1.2')

			if (r.success)
				r.res.elements.each('EngineConfigResponse/EngineConfig') do |v|
					@id = v.attributes['id']
					@address = v.attributes['address']
					@name = v.attributes['name']
					@port = v.attributes['port']
					@scope = v.attributes['scope']
					v.elements.each('Site') do |s|
						@sites << s.attributes['id']
					end
				end
			else
				@error = true
				@error_msg = 'EngineConfigRequest Parse Error'
			end
		end

		def save

		end
	end

end