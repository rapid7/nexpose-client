module Eso
  class Service
    attr_accessor :host

    attr_accessor :port

    attr_accessor :url

    CONTENT_TYPE_JSON = 'application/json; charset-utf-8'

    def initialize(host:, port: 3780, nsc:)
      @host = host
      @port = port
      @nexpose_console = nsc
    end

    def get(url:, content_type: CONTENT_TYPE_JSON)
      get = Net::HTTP::Get.new(url)
      get.set_content_type(content_type)
      request(request: get)
    end

    def put(url:, payload:, content_type: CONTENT_TYPE_JSON)
      put = Net::HTTP::Put.new(url)
      put.set_content_type(content_type)
      put.body = payload.to_s if payload
      request(request: put)
    end

    def post(url:, payload: nil, content_type: CONTENT_TYPE_JSON)
      post = Net::HTTP::Post.new(url)
      post.set_content_type(content_type)
      post.body = payload.to_s if payload
      request(request: post)
    end

    def delete(url:, content_type: CONTENT_TYPE_JSON)
      delete = Net::HTTP::Delete.new(url)
      delete.set_content_type(content_type)
      request(request: delete)
    end

    def http(timeout:)
      http = Net::HTTP.new(@host, @port)
      http.read_timeout = timeout if timeout
      http.use_ssl = false
      http
    end

    def https(timeout:)
      http = Net::HTTP.new(@host, @port)
      http.read_timeout = timeout if timeout
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http
    end

    def add_nexpose_session(request:)
      request.add_field('nexposeCCSessionID', @nexpose_console.session_id)
      request.add_field('Cookie', "nexposeCCSessionID=#{@nexpose_console.session_id}")
      request.add_field('X-Requested-With', 'XMLHttpRequest')
    end

    def request(request:, timeout: nil)
      http = https(timeout: timeout)
      add_nexpose_session(request: request)
      response = http.request(request)
      case response
        when Net::HTTPOK, Net::HTTPCreated
          rv = nil
          if response.content_type == "application/json" && !response.body.empty?
            json_data = JSON.parse(response.body, symbolize_names: true)
            json_data[:data].nil? ? rv = json_data : rv = json_data[:data]
          end
          rv
        when Net::HTTPForbidden
          raise "Access denied. Response was #{response.body}"
        else
          raise "There was an error sending the request. Response was #{response.body}"
      end
    end
  end
end
