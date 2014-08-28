module Nexpose

  # === Description
  # Object that represents a connection to a Nexpose Security Console.
  #
  # === Examples
  #   # Create a new Nexpose::Connection on the default port
  #   nsc = Connection.new('10.1.40.10', 'nxadmin', 'password')
  #
  #   # Create a new Nexpose::Connection from a URI or "URI" String
  #   nsc = Connection.from_uri('https://10.1.40.10:3780', 'nxadmin', 'password')
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
  #   # Logout
  #   logout_success = nsc.logout
  #
  class Connection
    include XMLUtils

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

    # A constructor to load a Connection object from a URI
    def self.from_uri(uri, user, pass, silo_id = nil)
      uri = URI.parse(uri)
      new(uri.host, user, pass, uri.port, silo_id)
    end

    # A constructor for Connection
    def initialize(ip, user, pass, port = 3780, silo_id = nil)
      @host = ip
      @port = port
      @username = user
      @password = pass
      @silo_id = silo_id
      @session_id = nil
      @url = "https://#{@host}:#{@port}/api/API_VERSION/xml"
    end

    # Establish a new connection and Session ID
    def login(wait = false)
      begin
        check_availability(wait)
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
    def execute(xml, version = '1.1', options = {})
      @request_xml = xml.to_s
      @api_version = version
      response = APIRequest.execute(@url, @request_xml, @api_version, options)
      @response_xml = response.raw_response_data
      response
    end

    def http_client(host, port, ssl = true)
      http = Net::HTTP.new(host, port)
      http.use_ssl = ssl
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE # XXX: security issue
      http
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
      http = http_client(@host, @port)
      headers = {'Cookie' => "nexposeCCSessionID=#{@session_id}"}
      resp = http.get(uri.to_s, headers)

      if file_name
        File.open(file_name, 'wb') { |file| file.write(resp.body) }
      else
        resp.body
      end
    end

    # Check if Nexpose is able to accept logins.
    # wait: retry connection if Nexpose is starting up or in maintenance mode
    # restarting: retry if Nexpose is restarting and drops connections
    # timeout: seconds to continue retrying connection
    def check_availability(wait = false, restarting = false, timeout = 300)
      http = http_client(@host, @port)

      begin
        while (timeout -= 5) > 0
          response = http.get('/login.html')
          case response
          when Net::HTTPOK then
            return
          when Net::HTTPRedirection then
            if wait
              if response['location'].downcase.include? 'starting.html'
                sleep 5
                next
              elsif response['location'].downcase.include? 'maintenance-login.html'
                restarting = true
                sleep 5
                next
              end
            end
          end
        end
        raise APIError.new(response, 'Nexpose is not accepting logins')
      rescue ::Errno::ECONNRESET, ::Errno::ECONNREFUSED, ::Errno::ENOTCONN, ::Errno::ECONNABORTED, OpenSSL::SSL::SSLError => e
        if restarting
          if (retries -= 5) > 0
            sleep 5
            retry
          end
        end
        raise e
      end

    end

  end
end
