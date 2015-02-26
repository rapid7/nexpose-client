module Nexpose

  class Connection

    # Retrieve information about all available connections for dynamic
    # discovery of assets, including whether or not connections are active.
    #
    def list_discovery_connections
      xml = make_xml('DiscoveryConnectionListingRequest')
      response = execute(xml, '1.2')
      connections = []
      response.res.elements.each('DiscoveryConnectionListingResponse/DiscoveryConnectionSummary') do |conn|
        connections << DiscoveryConnection.parse(conn)
      end
      connections
    end
    alias_method :discovery_connections, :list_discovery_connections

    # Delete an existing connection to a target used for dynamic discovery of assets.
    #
    # @param [Fixnum] id ID of an existing discovery connection.
    #
    def delete_discovery_connection(id)
      xml = make_xml('DiscoveryConnectionDeleteRequest', { 'id' => id })
      response = execute(xml, '1.2')
      response.success
    end
  end

  class DiscoveryConnection < APIObject
    include XMLUtils

    module Protocol
      HTTP = 'HTTP'
      HTTPS = 'HTTPS'
      LDAP = 'LDAP'
      LDAPS = 'LDAPS'
    end

    module Type
      VSPHERE = 'VSPHERE'
      AWS = 'AWS'
      ACTIVESYNC = 'ACTIVESYNC'
    end

    # A unique identifier for this connection.
    attr_accessor :id

    # A unique name for this connection.
    attr_accessor :name

    # Type of discovery connection
    attr_accessor :type

    # The IP address or fully qualified domain name of the server.
    attr_accessor :address

    # A user name that can be used to log into the server.
    attr_accessor :user

    # The password to use when connecting with the defined user.
    attr_accessor :password

    # The protocol used for conneting to the server. One of DiscoveryConnection::Protocol
    attr_accessor :protocol

    # The port used for connecting to the server. A valid port from 1 to 65535.
    attr_accessor :port

    # Whether or not the connection is active.
    # Discovery is only possible when the connection is active.
    attr_accessor :status

    # Create a new discovery connection.
    #
    # @param [String] name Name to assign to this connection.
    # @param [String] address IP or fully qualified domain name of the
    #    connection server.
    # @param [String] user User name for credentials on this connection.
    # @param [String] password Password for credentials on this connection.
    #
    def initialize(name = nil, address = nil, user = nil, password = nil)
      @name, @address, @user, @password = name, address, user, password
      @type = nil  # for backwards compatibilitly, at some point should set this to Type::VSPHERE
      @id = -1
      @port = 443
      @protocol = Protocol::HTTPS
    end

    # Save this discovery connection to a Nexpose console.
    #
    # @param [Connection] nsc Connection to a console.
    #
    def save(nsc)
      if @id == -1
        xml = nsc.make_xml('DiscoveryConnectionCreateRequest')
      else
        xml = nsc.make_xml('DiscoveryConnectionUpdateRequest')
      end
      xml.add_element(as_xml)
      response = nsc.execute(xml, '1.2')
      if response.success
        ret = REXML::XPath.first(response.res, 'DiscoveryConnectionCreateResponse')
        @id = ret.attributes['id'].to_i unless ret.nil?
      end
      @id
    end

    # Perform dynamic discover of assets against this connection.
    #
    # @param [Connection] nsc Connection to a console.
    # @param [Criteria] criteria Criteria search object narrowing which assets
    #   to filter.
    # @return [Array[DiscoveredAsset]] All discovered assets matching the criteria.
    #
    def discover(nsc, criteria = nil)
      parameters = { 'table-id' => 'assetdiscovery',
                     'sort' => 'assetDiscoveryName',
                     'searchCriteria' => criteria.nil? ? 'null' : criteria.to_json,
                     'configID' => @id }
      data = DataTable._get_json_table(nsc, '/data/discoveryAsset/discoverAssets', parameters)
      data.map { |a| DiscoveredAsset.parse(a) }
    end

    # Initiates a connection to a target used for dynamic discovery of assets.
    # As long as a connection is active, dynamic discovery is continuous.
    #
    # @param [Connection] nsc Connection to a console.
    #
    def connect(nsc)
      xml = nsc.make_xml('DiscoveryConnectionConnectRequest', { 'id' => id })
      response = nsc.execute(xml, '1.2')
      response.success
    end

    # Delete this connection from the console.
    #
    # @param [Connection] nsc Connection to a console.
    #
    def delete(nsc)
      nsc.delete_discovery_connection(@id)
    end

    def as_xml
      xml = REXML::Element.new('DiscoveryConnection')
      xml.attributes['name']      = @name
      xml.attributes['address']   = @address
      xml.attributes['port']      = @port
      xml.attributes['protocol']  = @protocol
      xml.attributes['user-name'] = @user
      xml.attributes['password']  = @password
      xml.attributes['type']      = @type if @type
      xml
    end

    def to_xml
      as_xml.to_s
    end

    def self.parse(xml)
      conn = new(xml.attributes['name'],
                 xml.attributes['address'],
                 xml.attributes['user-name'])
      conn.id = xml.attributes['id'].to_i
      conn.protocol = xml.attributes['protocol']
      conn.port = xml.attributes['port'].to_i
      conn.status = xml.attributes['connection-status']
      conn
    end

    def to_json
      JSON.generate(to_h)
    end

    def to_h
      { id: id,
        name: name,
        type: type
        # TODO Add remaining instance fields, once it is introduced in resource object
      }
    end

    def <=>(other)
      c = id <=> other.id
      return c unless c == 0
      c = name <=> other.name
      return c unless c == 0
      type <=> other.type
      # TODO Add remaining instance fields, once it is introduced in resource object
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      id.eql?(other.id) &&
      name.eql?(other.name) &&
      type.eql?(other.type)
      # TODO Add remaining instance fields, once it is introduced in resource object
    end

    # Override of filter criterion to account for proper JSON naming.
    #
    class Criterion < Nexpose::Criterion
      # Convert to Hash, which can be converted to JSON for API calls.
      def to_h
        { operator: operator,
          values: Array(value),
          field_name: field }
      end

      # Create a Criterion object from a JSON-derived Hash.
      #
      # @param [Hash] json JSON-derived Hash of a Criterion object.
      # @return [Criterion] Parsed object.
      #
      def self.parseHash(hash)
        Criterion.new(hash[:field_name],
                      hash[:operator],
                      hash[:values])
      end
    end

    # Override of filter criteria to account for different parsing from JSON.
    #
    class Criteria < Nexpose::Criteria
      # Create a Criteria object from a Hash.
      #
      # @param [Hash] Hash of a Criteria object.
      # @return [Criteria] Parsed object.
      #
      def self.parseHash(hash)
        # The call returns empty JSON, so default to 'AND' if not present.
        operator = hash[:operator] || 'AND'
        ret = Criteria.new([], operator)
        hash[:criteria].each do |c|
          ret.criteria << Criterion.parseHash(c)
        end
        ret
      end
    end
  end

  class DiscoveredAsset

    attr_accessor :name
    attr_accessor :ip
    attr_accessor :host
    attr_accessor :datacenter
    attr_accessor :cluster
    attr_accessor :pool
    attr_accessor :os
    attr_accessor :status

    def initialize(&block)
      instance_eval &block if block_given?
    end

    def on?
      @status == 'On'
    end

    def self.parse(json)
      new do |asset|
        asset.ip = json['IPAddress']
        asset.os = json['OSName']
        asset.name = json['assetDiscoveryName']
        asset.cluster = json['cluster']
        asset.datacenter = json['datacenter']
        asset.host = json['host']
        asset.status = json['powerStatus']
        asset.pool = json['resourcePool']
      end
    end
  end

  class MobileDiscoveryConnection < DiscoveryConnection
    # Create a new Mobile discovery connection.
    #
    # @param [String] name Name to assign to this connection.
    # @param [DiscoveryConnection::Protocol] protocol The protocol to use for discovery - LDAPS or LDAP
    # @param [String] address IP or fully qualified domain name of the
    #    connection server.
    # @param [String] user User name for credentials on this connection.
    # @param [String] password Password for credentials on this connection.
    #
    def initialize(name, protocol, address, user, password = nil)
      @name, @protocol, @address, @user, @password = name, protocol, address, user, password
      @type = Type::ACTIVESYNC
      @id = -1
      @port = 443   #port not used for mobile connection
    end

  end
end
