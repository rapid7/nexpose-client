module Eso
##
# This class represents a configuration manager service, which manages a number of configurations (ie a hostname,
# port, username, and password) used to connect to services, and the services they connect to (ie, ePO, dxl, palo-alto).
#
  class ConfigurationManager
    attr_accessor :url, :nexpose_console

    ##
    # Constructor for ConfigurationManager.
    #
    # @param [Nexpose::Connection] nsc A logged-in Nexpose::Connection object with a valid session used to authenticate.
    # @return [Eso::ConfigurationManager] The newly created configurationManager object
    #
    def initialize(nsc)
      @nexpose_console = nsc
      @url = "https://#{nsc.host}:#{nsc.port}/eso/configuration-manager/api/"
    end

    ##
    # Return all of the services that are currently supported by this configuration manager.
    #
    # @return [Array] An array containing all of services in the configuration manager in String object form.
    #                 Returns an empty array if no services have been configured.
    #
    def services
      json_data = ::Nexpose::AJAX.get(@nexpose_console, "#{@url}service/", ::Nexpose::AJAX::CONTENT_TYPE::JSON)
      JSON.parse(json_data)
    end

    ##
    # Return all of the configurations of a particular service type.
    #
    # @param [String] service_name The name of a service to find configurations of.
    # @return [Array] An array containing all the configurations of the given service type.
    #
    def service_configurations(service_name)
      json_data = ::Nexpose::AJAX.get(@nexpose_console,
                                    "#{@url}service/configuration/#{service_name}/",
                                    ::Nexpose::AJAX::CONTENT_TYPE::JSON)
      JSON.parse(json_data, :symbolize_names => true)
    end

    ##
    # Return the configuration of a particular service type with a particular name.
    #
    # @param [String] service_name The name of a service to find configurations of.
    # @param [String] config_name The name of the Configuration.
    # @return [Eso::Configuration] A Configuration object which matches the service name and config name requested.
    def configuration_by_name(service_name, config_name)
      service_configs_by_type =  service_configurations(service_name)
      config_hash = service_configs_by_type.find { |config| config[:configName] == config_name }
      Eso::Configuration.load(config_hash)
    end

    def configuration_type(service_name:)
      json_data = ::Nexpose::AJAX.get(@nexpose_console,
                                    "#{@url}service/configurationType/#{service_name.downcase}",
                                    ::Nexpose::AJAX::CONTENT_TYPE::JSON)
      JSON.parse(json_data)
    end

    ##
    # Get a configuration by id. Runs a GET call against the eso/configuration-manager/api/service/configuration/CONFIGURATION_ID endpoint
    # @param [String] configuration_id The id of the configuration to get
    # return [JSON] A json object representing a configuration
    # TODO : Update to use an Eso::Configuration
    def get_configuration(configuration_id)
      json_data = ::Nexpose::AJAX.get(@nexpose_console, "#{@url}/service/configuration/id/#{configuration_id}", ::Nexpose::AJAX::CONTENT_TYPE::JSON)
      JSON.parse(json_data, :symbolize_names => true)
    end

    ##
    # Create a new configuration.
    #
    # @param [String] payload The JSON representation of a configuration.
    # @return [Integer] The configID (>= 1) of the newly created configuration. Raises error on failure.
    # TODO: Update to use an Eso::Configuration
    def post_service_configuration(payload)
      # TODO retry if the post fails on timeout
      response_body = ::Nexpose::AJAX.post(@nexpose_console, "#{@url}service/configuration", payload, ::Nexpose::AJAX::CONTENT_TYPE::JSON)
      config_id = Integer(JSON.parse(response_body)['data'])
      raise Exception.new("API returned invalid configID (#{config_id}) while attempting to create configuration.") unless config_id >= 1
      config_id
    end

    ##
    # Test a configuration.
    #
    # @param [String] payload The JSON representation of a configuration.
    # @return [String] The response from the call or an APIError
    # TODO: Update to use an Eso::Configuration
    def test_service_configuration(payload)
      ::Nexpose::AJAX.post(@nexpose_console,
                         "#{@url}service/configuration/test",
                         payload,
                         ::Nexpose::AJAX::CONTENT_TYPE::JSON)
    end

    ##
    # Delete a configuration. Runs a DELETE call against the eso/configuration-manager/api/service/configuration/CONFIGURATION_ID endpoint
    #
    # @param [String] configuration_id The id of the configuration to delete
    # return [Boolean] Return true if the api reports a successful delete. Raises an error on failure.
    def delete(configuration_id)
      response_body = ::Nexpose::AJAX.delete(@nexpose_console, "#{@url}service/configuration/#{configuration_id}")
      raise Exception.new("Failed to delete configuration with ID: #{configuration_id}") unless 'success' == response_body
      true
    end

    ##
    # Preview assets for a configuration. Calls a POST to the eso/configuration-manager/api/service/configuration/preview endpoint
    #
    # @param configuration The configuration to preview
    # return [Array] previewed assets
    # TODO: Update to use an Eso::Configuration
    def preview_assets(configuration)
      response_body = ::Nexpose::AJAX.post(@nexpose_console,
                                         "#{@url}service/configuration/preview",
                                         configuration,
                                         ::Nexpose::AJAX::CONTENT_TYPE::JSON)
      @preview_assets = JSON.parse(response_body)["previewAssets"]
    end
  end

  module ConfigManagerMessages
    module TestConfig
      AUTH_FAILED_AWS       = 'Could not authenticate to Amazon Web Services.'
      # Actual message will list out the bad ARNs
      AUTH_FAILED_AWS_ARN   = /Could not authenticate to Amazon Web Services with the following ARNs/

      CONNECTION_SUCCESSFUL = 'The connection to the external service was successful.'
      # Applies to invalid user, password, wrong protocol, can't reach server, bad base or search query
      CONNECTION_FAILED     = 'The connection to the external service failed.'

      INVALID_FIELDS        = 'The configuration had invalid fields.'

      RETRY_AD              = 'Failed to reach out to the Active Directory service, will try again.'
      RETRY_AWS             = 'Failed to reach out to Amazon Web Services, will try again.'
      RETRY_AZURE           = 'Failed to reach out to the Azure service, will try again.'
      RETRY_DXL             = 'The DXL connection is currently down and the connection is in retry status.'
      RETRY_EPO             = 'Failed to reach out to the ePO service, will try again.'
    end
  end
end
