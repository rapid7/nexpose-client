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

		def initialize(connection, id = -1)
			@connection = connection
			@id = id
			@address = nil
			@name = nil
			@port = 40814
			@scope = 'silo'
			@priority = 'normal'
			@sites = []

      # If valid ID provided, retrieve data from server.
      if (id > 0)
        xml = '<EngineConfigRequest session-id="' + @connection.session_id + '"'
        xml << %Q{ engine-id="#{id}"}
        xml << ' />'
        r = @connection.execute(xml, '1.2')

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
    end

    def to_xml
      xml = '<EngineConfig'
      xml << %Q{ id="#{id}"}
      xml << %Q{ address="#{address}"}
      xml << %Q{ name="#{name}"}
      xml << %Q{ port="#{port}"}
      xml << %Q{ scope="#{scope}"}
      xml << %Q{ priority="#{priority}"} if (priority)
      # TODO: xml << %Q{ sites="#{sites}"} if (sites)
      xml << ' />'
      xml
    end

    # Save this engine configuration
    # Example usage:
    #   engine = EngineConfig.new(@nsc)
    #   engine.address = 'atlanta.company.com'
    #   engine.name = 'Atlanta Engine'
    #   engine.save()
    def save
      xml = '<EngineSaveRequest session-id="' + @connection.session_id + '">'
      xml << to_xml
      xml << '</EngineSaveRequest>'

      r = @connection.execute(xml, '1.2')
      unless (r.success)
        @error = true
        @error_msg = 'EngineSaveRequest Parse Error'
      end
    end
  end

  #-------------------------------------------------------------------------------------------------------------------
  # Core objects for creating an engine pool
  # Example usage:
  #   pool = EnginePool.new('East Coast Pool')
  #   pool.add('New York Engine')
  #   pool.add('Georgia Engine')
  #   id = pool.create(@nsc)
  #-------------------------------------------------------------------------------------------------------------------
	class EnginePool
		attr_accessor :name
		attr_accessor :scope
		attr_accessor :engines

		def initialize(name, scope = 'silo')
			@name = name
			@scope = scope
      @engines = []
    end

    # Add an engine to the pool by name (not ID).
    def add(engine)
      engines << engine
    end

    # Create an engine pool from the existing configuration.
    # Returns the engine ID assigned to the pool, if successful.
    def create(connection)
      xml = '<EnginePoolCreateRequest session-id="' + connection.session_id + '">'
      xml << %Q{<EnginePool name="#{name}" scope="#{scope}">}
      engines.each do |engine|
        xml << %Q{<Engine name="#{engine}" />}
      end
      xml << '</EnginePool>'
      xml << '</EnginePoolCreateRequest>'

      r = connection.execute(xml, '1.2')
      if (r.success)
        r.res.elements.each('EnginePoolCreateResponse') do |v|
          return v.attributes['id']
        end
      else 
        @error = true
        @error_msg = 'EnginePoolCreateResponse Parse Error'
      end
    end
  end
end
