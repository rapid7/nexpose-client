module Nexpose
  module NexposeAPI
    include XMLUtils

    # Removes a scan engine from the list of available engines.
    def delete_engine(engine_id)
      xml = make_xml('EngineDeleteRequest', {'engine-id' => engine_id})
      execute(xml, '1.2')
    end

    # Provide a list of current scan activities for a specific Scan Engine.
    #
    # @return [Array[ScanSummary]] Array of ScanSummary objects associated with
    #   each active scan on the engine.
    #
    def engine_activity(engine_id)
      xml = make_xml('EngineActivityRequest', {'engine-id' => engine_id})
      r = execute(xml)
      arr = []
      if r.success
        r.res.elements.each("//ScanSummary") do |scan_event|
          arr << ScanSummary.parse(scan_event)
        end
      end
      arr
    end

    # Retrieve a list of all Scan Engines managed by the Security Console.
    #
    # @return [Array[EngineSummary]] Array of EngineSummary objects associated with
    #   each engine associated with this security console.
    #
    def list_engines
      response = execute(make_xml('EngineListingRequest'))
      arr = []
      if response.success
        response.res.elements.each("//EngineSummary") do |engine|
          arr << EngineSummary.new(engine.attributes['id'].to_i,
                                   engine.attributes['name'],
                                   engine.attributes['address'],
                                   engine.attributes['port'].to_i,
                                   engine.attributes['status'])
        end
      end
      arr
    end

    alias_method :engines, :list_engines
  end

  # Object representing the current details of a scan engine attached to the security console.
  #
  class EngineSummary

    # A unique ID that identifies this scan engine.
    attr_reader :id
    # The name of this scan engine.
    attr_reader :name
    # The hostname or IP address of the engine.
    attr_reader :address
    # The port there the engine is listening.
    attr_reader :port
    # The engine status. One of: active|pending-auth|incompatible|not-responding|unknown
    attr_reader :status
    # A parameter that specifies whether the engine has a global
    # or silo-specific scope.
    attr_reader :scope

    def initialize(id, name, address, port, status, scope = 'silo')
      @id = id
      @name = name
      @address = address
      @port = port
      @status = status
      @scope = scope
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
      if id > 0
        xml = '<EngineConfigRequest session-id="' + @connection.session_id + '"'
        xml << %Q{ engine-id="#{id}"}
        xml << ' />'
        r = @connection.execute(xml, '1.2')

        if r.success
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

    def add_site(site_id)
      sites << site_id
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
      sites.each do |site|
        xml << %Q{<Site id="#{site}" />}
      end
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
      if r.success
        r.res.elements.each('EngineSaveResponse/EngineConfig') do |v|
          return @id = v.attributes['id']
        end
      else (r.success)
        @error = true
        @error_msg = 'EngineSaveRequest Parse Error'
      end
    end

    def delete
      @connection.delete_engine(@id)
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
      xml << %Q{<EnginePool name="#@name" scope="#@scope">}
      @engines.each do |engine|
        xml << %Q{<Engine name="#{engine.name}" />}
      end
      xml << '</EnginePool>'
      xml << '</EnginePoolCreateRequest>'

      r = connection.execute(xml, '1.2')
      if r.success
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
      xml << %Q{<EnginePool name="#@name" scope="#@scope" />}
      xml << '</EnginePoolDeleteRequest>'

      r = connection.execute(xml, '1.2')
      unless r.success
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
      xml << %Q{<EnginePool id="#@id" name="#@name" scope="#@scope">}
      @engines.each do |engine|
        xml << %Q{<Engine name="#{engine.name}" />}
      end
      xml << '</EnginePool>'
      xml << '</EnginePoolUpdateRequest>'

      r = connection.execute(xml, '1.2')
      if r.success
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
      xml << %Q{<EnginePool name="#@name" scope="#@scope" />}
      xml << '</EnginePoolDetailsRequest>'

      r = connection.execute(xml, '1.2')
      if r.success
        r.res.elements.each('EnginePoolDetailsResponse/EnginePool') do |pool|
          @id = pool.attributes['id']
          @name = pool.attributes['name']
          @scope = pool.attributes['scope']
          @engines = []
          r.res.elements.each('EnginePoolDetailsResponse/EnginePool/EngineSummary') do |summary|
            @engines.push(EngineSummary.new(summary.attributes['id'].to_i,
                                            summary.attributes['name'],
                                            summary.attributes['address'],
                                            summary.attributes['port'].to_i,
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
      "Engine Pool: #@name [ID: #@id], Scope: #@scope\n" + @engines.map { |engine| "  #{engine}" }.join("\n")
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
      "Engine Pool: #@name [ID: #@id], scope: #@scope"
    end

    # Returns a summary list of all engine pools.
    def self.listing(connection)
      xml = '<EnginePoolListingRequest session-id="' + connection.session_id + '" />'
      r = connection.execute(xml, '1.2')
      if r.success
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
