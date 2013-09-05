module Nexpose

  # === Description
  # Object that represents a connection to a Nexpose Security Console.
  #
  # === Examples
  #   # Create a new Nexpose Connection on the default port
  #   nsc = Connection.new('10.1.40.10', 'nxadmin', 'password')
  #
  #   # Login to NSC and Establish a Session ID
  #   nsc.login
  #
  #   # Check Session ID
  #   if nsc.session_id
  #       puts 'Login Successful'
  #   else
  #       puts 'Login Failure'
  #   end
  #
  #   # //Logout
  #   logout_success = nsc.logout
  #
  class Connection
    include XMLUtils
    include NexposeAPI

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

    # The last XML request sent by this object, useful for debugging.
    attr_reader :request_xml
    # The last XML response received by this object, useful for debugging.
    attr_reader :response_xml

    # Constructor for Connection
    def initialize(ip, user = nil, pass = nil, port = 3780, silo_id = nil)
      # If the user specified a URI, parse it
      if [URI::HTTP, URI::HTTPS].include? ip.class
        user = ip.user
        pass = ip.password
        port = ip.port

# TODO: Add support for custom paths (allows a user to specify the API
#   endpoint)
#        if ip.path =~ /^\/api\/\S+\/xml$/
#          path = ip.path
#        else
#          # TODO: API_VERSION should be a constant (Nexpose::API_VERSION) which holds the latest version
#          # Nexpose::API_VERSION = 'v1'; "api/#{Nexpose::API_VERSION}/xml"
#          path = 'api/API_VERSION/xml'
#        end
          
        ip = ip.host
      end
      
      raise ArgumentError, "wrong number of arguments (1 for 3..5)" if user.nil?
      raise ArgumentError, "wrong number of arguments (2 for 3..5)" if pass.nil?

      @host = ip
      @port = port
      @username = user
      @password = pass
      @silo_id = silo_id
      @session_id = nil
      @url = File.join("https://#{@host}:#{@port}", '/api/API_VERSION/xml')
    end

    # Establish a new connection and Session ID
    def login
      begin
        login_hash = {'sync-id' => 0, 'password' => @password, 'user-id' => @username}
        login_hash['silo-id'] = @silo_id if @silo_id
        r = execute(make_xml('LoginRequest', login_hash))
        if r.success
          @session_id = r.sid
          true
        end
      rescue APIError
        raise AuthenticationFailed.new(r)
      end
    end

    # Logout of the current connection
    def logout
      r = execute(make_xml('LogoutRequest', {'sync-id' => 0}))
      return true if r.success
      raise APIError.new(r, 'Logout failed')
    end

    # Execute an API request
    def execute(xml, version = '1.1')
      @request_xml = xml.to_s
      @api_version = version
      response = APIRequest.execute(@url, @request_xml, @api_version)
      @response_xml = response.raw_response_data
      response
    end

    # Download a specific URL, typically a report.
    # Include an optional file_name parameter to write the output to a file.
    #
    # Note: XML and HTML reports have charts not downloaded by this method.
    #       Would need to do something more sophisticated to grab
    #       all the associated image files.
    def download(url, file_name = nil)
      return nil if url.nil? or url.empty?
      uri = URI.parse(url)
      http = Net::HTTP.new(@host, @port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE # XXX: security issue
      headers = {'Cookie' => "nexposeCCSessionID=#{@session_id}"}
      resp = http.get(uri.to_s, headers)

      if file_name
        File.open(file_name, 'w') { |file| file.write(resp.body) }
      else
        resp.body
      end
    end
  end
end
