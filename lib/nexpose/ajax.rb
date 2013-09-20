# encoding: utf-8

module Nexpose

  # Accessor to the Nexpose AJAX API.
  # These core methods should allow direct access to underlying controllers
  # in order to test functionality that is not currently exposed
  # through the XML API.
  #
  module AJAX
    module_function

    # GET call to a Nexpose controller.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] uri Controller address relative to https://host:port
    # @param [String] content_type Content type to use when issuing the GET.
    # @return [String|REXML::Document|Hash] The response from the call.
    #
    def get(nsc, uri, content_type = 'text/xml; charset=UTF-8')
      get = Net::HTTP::Get.new(uri)
      get.set_content_type(content_type)
      _request(nsc, get)
    end

    # PUT call to a Nexpose controller.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] uri Controller address relative to https://host:port
    # @param [String|REXML::Document] payload XML document required by the call.
    # @param [String] content_type Content type to use when issuing the PUT.
    # @return [String] The response from the call.
    #
    def put(nsc, uri, payload = nil, content_type = 'text/xml; charset=UTF-8')
      put = Net::HTTP::Put.new(uri)
      put.set_content_type(content_type)
      put.body = payload.to_s if payload
      _request(nsc, put)
    end

    # POST call to a Nexpose controller.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] uri Controller address relative to https://host:port
    # @param [String|REXML::Document] payload XML document required by the call.
    # @param [String] content_type Content type to use when issuing the POST.
    # @return [String|REXML::Document|Hash] The response from the call.
    #
    def post(nsc, uri, payload = nil, content_type = 'text/xml')
      post = Net::HTTP::Post.new(uri)
      post.set_content_type(content_type)
      post.body = payload.to_s if payload
      _request(nsc, post)
    end

    # POST call to a Nexpose controller that uses a form-post model.
    # This is here to support legacy use of POST in old controllers.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] uri Controller address relative to https://host:port
    # @param [Hash] parameters Hash of attributes that need to be sent
    #    to the controller.
    # @param [String] content_type Content type to use when issuing the POST.
    # @return [Hash] The parsed JSON response from the call.
    #
    def form_post(nsc, uri, parameters, content_type = 'application/x-www-form-urlencoded; charset=UTF-8')
      post = Net::HTTP::Post.new(uri)
      post.set_content_type(content_type)
      post.set_form_data(parameters)
      _request(nsc, post)
    end

    # DELETE call to a Nexpose controller.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] uri Controller address relative to https://host:port
    # @param [String] content_type Content type to use when issuing the DELETE.
    def delete(nsc, uri, content_type = 'text/xml')
      delete = Net::HTTP::Delete.new(uri)
      delete.set_content_type(content_type)
      _request(nsc, delete)
    end

    # Append the query parameters to given URI.
    #
    # @param [String] uri Controller address relative to https://host:port
    # @param [Hash] parameters Hash of attributes that need to be sent
    #    to the controller.
    # @return [Hash] The parametrized URI.

    def parametrize_uri(uri, parameters)
      uri = uri.concat(('?').concat(parameters.map { |k, v| "#{k}=#{CGI.escape(v[0].to_s)}" }.join('&'))) if parameters
    end

    ###
    # Internal helper methods

    # Use the Nexpose::Connection to establish a correct HTTPS object.
    def _https(nsc)
      http = Net::HTTP.new(nsc.host, nsc.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http
    end

    # Attach necessary header fields.
    def _headers(nsc, request)
      request.add_field('nexposeCCSessionID', nsc.session_id)
      request.add_field('Cookie', "nexposeCCSessionID=#{nsc.session_id}")
    end

    def _request(nsc, request)
      http = _https(nsc)
      _headers(nsc, request)

      # Return response body if request is successful. Brittle.
      response = http.request(request)
      case response
      when Net::HTTPOK
        response.body
      else
        req_type = request.class.name.split('::').last.upcase
        raise Nexpose::APIError.new(response, "#{req_type} request to #{request.path} failed. #{request.body}")
      end
    end
  end
end
