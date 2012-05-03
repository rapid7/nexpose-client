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
    # A parameter that specifies whether the engine has a global
    # or silo-specific scope.
    attr_reader :scope

    # Constructor
    # EngineSummary(id, name, address, port, status, scope)
    def initialize(id, name, address, port, status, scope = 'silo')
      @id = id
      @name = name
      @address = address
      @port = port
      @status = status
      @scope = scope
    end

    def to_s
      "Engine: #{@name} [ID: #{@id}] #{@address}:#{@port}, Status: #{@status}, Scope: #{@scope}"
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
    attr_accessor :priority

    # An array of site IDs. Currently do not support 'name' value,
    # which is optional in the API.
    attr_accessor :sites

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

    def add_site(siteID)
      sites << siteID
    end

    def to_xml
      xml = '<EngineConfig'
      xml << %Q{ id="#{id}"}
      xml << %Q{ address="#{address}"}
      xml << %Q{ name="#{name}"}
      xml << %Q{ port="#{port}"}
      xml << %Q{ scope="#{scope}"}
      xml << %Q{ priority="#{priority}"} if (priority)
      xml << '>'
      #sites.each do |site|
      #xml << %Q{<Site id="#{site}" />}
      #end
      xml << '</EngineConfig>'
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
      if (r.success)
        r.res.elements.each('EngineSaveResponse/EngineConfig') do |v|
          @id = v.attributes['id']
        end
      else (r.success)
        @error = true
        @error_msg = 'EngineSaveRequest Parse Error'
      end
    end
  end

  # Core objects for creating an engine pool
  # Example usage:
  #   pool = EnginePool.new('East Coast Pool')
  #   pool.add('New York Engine')
  #   pool.add('Georgia Engine')
  #   pool.create(@nsc)
  class EnginePool
    attr_accessor :id
    attr_accessor :name
    attr_accessor :scope
    # Array containing (EngineSummary*)
    attr_accessor :engines

    def initialize(name, id = -1, scope = 'silo')
      @name = name
      @id = id
      @scope = scope
      @engines = []
    end

    # Add an engine to the pool by name (not ID).
    # Only use this for creating pools.
    def add(engine)
      @engines << EngineSummary.new(-1, engine, 'nowhere', 40814, 'unknown')
    end

    # Creates a new engine pool, and adds scan engines to the pool.
    def create(connection)
      xml = '<EnginePoolCreateRequest session-id="' + connection.session_id + '">'
      xml << %Q{<EnginePool name="#{@name}" scope="#{@scope}">}
      @engines.each do |engine|
        xml << %Q{<Engine name="#{engine.name}" />}
      end
      xml << '</EnginePool>'
      xml << '</EnginePoolCreateRequest>'

      r = connection.execute(xml, '1.2')
      if (r.success)
        r.res.elements.each('EnginePoolCreateResponse') do |v|
          @id = v.attributes['id']
        end
      else 
        @error = true
        @error_msg = 'EnginePoolCreateResponse Parse Error'
      end
    end

    # Deletes an engine pool
    def delete(connection)
      xml = '<EnginePoolDeleteRequest session-id="' + connection.session_id + '">'
      xml << %Q{<EnginePool name="#{@name}" scope="#{@scope}" />}
      xml << '</EnginePoolDeleteRequest>'

      r = connection.execute(xml, '1.2')
      unless (r.success)
        @error = true
        @error_msg = 'EnginePoolDeleteResponse Parse Error'
      end
    end

    # Updates a specific role with new information. An EnginePoolUpdate is
    # similar to an EnginePoolCreate, except that an EnginePoolUpdate replaces
    # any previously existing information with the new information specified in
    # the EnginePoolUpdateRequest.
    def update(connection)
      xml = '<EnginePoolUpdateRequest session-id="' + connection.session_id + '">'
      xml << %Q{<EnginePool id="#{@id}" name="#{@name}" scope="#{@scope}">}
      @engines.each do |engine|
        xml << %Q{<Engine name="#{engine.name}" />}
      end
      xml << '</EnginePool>'
      xml << '</EnginePoolUpdateRequest>'

      r = connection.execute(xml, '1.2')
      if (r.success)
        r.res.elements.each('EnginePoolUpdateResponse') do |v|
          @id = v.attributes['id']
        end
      else 
        @error = true
        @error_msg = 'EnginePoolCreateResponse Parse Error'
      end
    end

    # Returns detailed information about a single engine pool.
    def load_details(connection)
      xml = '<EnginePoolDetailsRequest session-id="' + connection.session_id + '">'
      xml << %Q{<EnginePool name="#{@name}" scope="#{@scope}" />}
      xml << '</EnginePoolDetailsRequest>'

      r = connection.execute(xml, '1.2')
      if (r.success)
        r.res.elements.each('EnginePoolDetailsResponse/EnginePool') do |pool|
          @id = pool.attributes['id']
          @name = pool.attributes['name']
          @scope = pool.attributes['scope']
          @engines = []
          r.res.elements.each('EnginePoolDetailsResponse/EnginePool/EngineSummary') do |summary|
            @engines.push(EngineSummary.new(summary.attributes['id'],
                                            summary.attributes['name'],
                                            summary.attributes['address'],
                                            summary.attributes['port'],
                                            summary.attributes['status'],
                                            summary.attributes['scope']))
          end
        end
      else 
        @error = true
        @error_msg = 'EnginePoolListingResponse Parse Error'
      end
    end

    def to_s
      "Engine Pool: #{@name} [ID: #{@id}], Scope: #{@scope}\n" + @engines.map { |engine| "  #{engine}" }.join("\n")
    end
  end

  # A summary of an engine pool.
  class EnginePoolSummary
    attr_reader :id
    attr_reader :name
    attr_reader :scope

    def initialize(id, name, scope = 'silo')
      @id = id
      @name = name
      @scope = scope
    end

    def to_s
      "Engine Pool: #{@name} [ID: #{@id}], scope: #{@scope}"
    end

    # Returns a summary list of all engine pools.
    def self.listing(connection)
      xml = '<EnginePoolListingRequest session-id="' + connection.session_id + '" />'
      r = connection.execute(xml, '1.2')
      if (r.success)
        list = []
        r.res.elements.each('EnginePoolListingResponse/EnginePoolSummary') do |eps|
          list << EnginePoolSummary.new(eps.attributes['id'], eps.attributes['name'], eps.attributes['scope'])
        end
        list
      else 
        @error = true
        @error_msg = 'EnginePoolListingResponse Parse Error'
      end
    end
  end
end
