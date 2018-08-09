require 'nexpose'

module Eso
  ##
  # This class is a manager for the integration options api. Integration options match epo/dxl/etc steps
  # (ie discover-epo-assets) to nexpose steps (ie import-external-assets).

  class IntegrationOptionsManager

    ##
    # Constructor for IntegrationOptionsManager.
    #
    # @param [Nexpose::Connection] nsc A logged-in Nexpose::Connection object with a valid session used to authenticate.
    # @return [Eso::IntegrationOptionsManager] The newly created IntegrationOptionManager object
    #
    def initialize(nsc)
      @nexpose_console = nsc
      @url = "https://#{nsc.host}:#{nsc.port}/eso/integration-manager-service/api/integration-options/"
    end

    ##
    # Create a new or Update existing integration option.
    #
    # @param [String] payload The JSON representation of an integration option.
    # @return [String] The integrationOptionID (a UUID) of the newly created configuration. Raises error on failure.
    #
    def create(payload)
      # TODO retry if the post fails on timeout
      response_body = ::Nexpose::AJAX.post(@nexpose_console, "#{@url}", payload, ::Nexpose::AJAX::CONTENT_TYPE::JSON)
      JSON.parse(response_body)['data']['id']
    end
    alias_method :update, :create

    # Deleting and stopping are the same thing
    def delete(integration_option_id)
      ::Nexpose::AJAX.delete(@nexpose_console, "#{@url}#{integration_option_id}/state")
    end
    alias_method :stop, :delete

    ##
    # Get an existing integration option.
    #
    # @param [String] integration_option_id The integration_option_id of the integration option.
    # @return IntegrationOption for that id, or nil
    #
    def get(integration_option_id)
      # Gets all integration options
      response_body = ::Nexpose::AJAX.get(@nexpose_console, "#{@url}", ::Nexpose::AJAX::CONTENT_TYPE::JSON)
      response = JSON.parse(response_body, symbolize_names: true)

      # Find the desired one
      raw_integration_option = response.find{|raw| raw[:id] == integration_option_id}
      raise "No IntegrationOption with ID #{integration_option_id}" if raw_integration_option.nil?

      # Load it to an object
      IntegrationOption.load(raw_integration_option)
    end

    ##
    # Get the status of an integration option.
    #
    # @param [String] integration_option_id The integration_option_id of the integration option.
    # @return the state (READY, STOPPED, etc)
    #
    def status(integration_option_id)
      response_body = ::Nexpose::AJAX.get(@nexpose_console, "#{@url}#{integration_option_id}/status", ::Nexpose::AJAX::CONTENT_TYPE::JSON)
      response = JSON.parse(response_body)
      response['state']
    end

    def start(integration_option_id)
      response_body = ::Nexpose::AJAX.post(@nexpose_console, "#{@url}#{integration_option_id}/state", ::Nexpose::AJAX::CONTENT_TYPE::JSON)
      JSON.parse(response_body)
    end

    # TODO: These build_* methods must die.
    def self.build_import_epo_assets_option(name:, discovery_conn_id:, site_id: nil)
      step1 = Step.new(service_name: ServiceNames::EPO, type_name: StepNames::DISCOVER_EPO)
                  .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, discovery_conn_id)
      step2 = Step.new(service_name: ServiceNames::NEXPOSE, type_name: StepNames::IMPORT_EXTERNAL, previous_type_name: step1.type_name)

      #This isn't always known immediately, which is why we have IntegrationOption.site_id=
      step2.add_property(StepConfiguration::ConfigParamProperties::SITE_ID, site_id) if site_id
      IntegrationOption.new(name: name, steps: [step1, step2])
    end

    def self.build_import_ad_assets_option(name:, discovery_conn_id:, site_id: nil)
      step1 = Step.new(service_name: ServiceNames::ACTIVE_DIRECTORY, type_name: StepNames::DISCOVER_ACTIVE_DIRECTORY)
                  .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, discovery_conn_id)
      step2 = Step.new(service_name: ServiceNames::NEXPOSE, type_name: StepNames::IMPORT_EXTERNAL, previous_type_name: step1.type_name)

      #This isn't always known immediately, which is why we have IntegrationOption.site_id=
      step2.add_property(StepConfiguration::ConfigParamProperties::SITE_ID, site_id) if site_id
      IntegrationOption.new(name: name, steps: [step1, step2])
    end

    def self.build_sync_aws_assets_option(name:, discovery_conn_id:, site_id: nil)
      step1 = Step.new(service_name: ServiceNames::AWS, type_name: StepNames::DISCOVER_AWS_ASSETS)
                  .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, discovery_conn_id)
      step2 = Step.new(service_name: ServiceNames::NEXPOSE, type_name: StepNames::SYNC_EXTERNAL, previous_type_name: step1.type_name)

      #This isn't always known immediately, which is why we have IntegrationOption.site_id=
      step2.add_property(StepConfiguration::ConfigParamProperties::SITE_ID, site_id) if site_id
      IntegrationOption.new(name: name, steps: [step1, step2])
    end

    def self.build_verify_aws_targets_option(name:, discovery_conn_id:)
      step1 = Step.new(service_name: ServiceNames::AWS, type_name: StepNames::VERIFY_AWS_ASSETS)
                  .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, discovery_conn_id)
      step2 = Step.new(service_name: ServiceNames::NEXPOSE, type_name: StepNames::VERIFY_EXTERNAL_TARGETS,
                       previous_type_name: step1.type_name)
      step3 = Step.new(service_name: ServiceNames::AWS, type_name: StepNames::VERIFY_AWS_ASSETS,
                       previous_type_name: step2.type_name)
                  .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, discovery_conn_id)

      IntegrationOption.new(name: name, steps: [step1, step2, step3])
    end

    def self.build_sync_azure_assets_option(name:, discovery_conn_id:, site_id: nil)
      step1 = Step.new(service_name: ServiceNames::AZURE, type_name: StepNames::DISCOVER_AZURE_ASSETS)
                  .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, discovery_conn_id)
      step2 = Step.new(service_name: ServiceNames::NEXPOSE, type_name: StepNames::SYNC_EXTERNAL, previous_type_name: step1.type_name)

      #This isn't always known immediately, which is why we have IntegrationOption.site_id=
      step2.add_property(StepConfiguration::ConfigParamProperties::SITE_ID, site_id) if site_id
      IntegrationOption.new(name: name, steps: [step1, step2])
    end

    def self.build_sync_aws_assets_with_tags_option(name:, discovery_conn_id:, site_id: nil, tags: '')
      step1 = Step.new(service_name: ServiceNames::AWS, type_name: StepNames::DISCOVER_AWS_ASSETS)
                  .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, discovery_conn_id)
                  .add_property(StepConfiguration::ConfigParamProperties::IMPORT_TAGS, true)
                  .add_property(StepConfiguration::ConfigParamProperties::EXCLUDE_ASSETS_WITH_TAGS, "")
                  .add_property(StepConfiguration::ConfigParamProperties::ONLY_IMPORT_THESE_TAGS, tags)
      step2 = Step.new(service_name: ServiceNames::NEXPOSE, type_name: StepNames::SYNC_EXTERNAL, previous_type_name: step1.type_name)

      #This isn't always known immediately, which is why we have IntegrationOption.site_id=
      step2.add_property(StepConfiguration::ConfigParamProperties::SITE_ID, site_id) if site_id
      IntegrationOption.new(name: name, steps: [step1, step2])
    end

    def self.build_sync_azure_assets_with_tags_option(name:, discovery_conn_id:, site_id: nil, only_tags: '', exclude_tags: '')
      step1 = Step.new(service_name: ServiceNames::AZURE, type_name: StepNames::DISCOVER_AZURE_ASSETS)
                  .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, discovery_conn_id)
                  .add_property(StepConfiguration::ConfigParamProperties::IMPORT_TAGS, true)
                  .add_property(StepConfiguration::ConfigParamProperties::EXCLUDE_ASSETS_WITH_TAGS, exclude_tags)
                  .add_property(StepConfiguration::ConfigParamProperties::ONLY_IMPORT_THESE_TAGS, only_tags)
      step2 = Step.new(service_name: ServiceNames::NEXPOSE, type_name: StepNames::SYNC_EXTERNAL, previous_type_name: step1.type_name)

      #This isn't always known immediately, which is why we have IntegrationOption.site_id=
      step2.add_property(StepConfiguration::ConfigParamProperties::SITE_ID, site_id) if site_id
      IntegrationOption.new(name: name, steps: [step1, step2])
    end

    def self.build_export_risk_scores_option(name:, discovery_conn_id:)
      step1 = Step.new(service_name: ServiceNames::NEXPOSE, type_name: StepNames::RISK_SCORE_UPDATED)
      step2 = Step.new(service_name: ServiceNames::EPO, type_name: StepNames::PUSH_RISK_SCORE, previous_type_name: step1.type_name)
                  .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, discovery_conn_id)
      IntegrationOption.new(name: name, steps: [step1, step2])
    end

    def self.build_find_vuln_details_option(name:, discovery_conn_id:)
      step1 = Step.new(service_name: ServiceNames::DXL, type_name: StepNames::VULN_DETAILS_REQUEST)
                  .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, discovery_conn_id)
      step2 = Step.new(service_name: ServiceNames::NEXPOSE, type_name: StepNames::VULN_DETAILS, previous_type_name: step1.type_name)
      step3 = Step.new(service_name: ServiceNames::DXL, type_name: StepNames::VULN_DETAILS_REQUEST, previous_type_name: step2.type_name)
                  .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, discovery_conn_id)
      IntegrationOption.new(name: name, steps: [step1, step2, step3])
    end

    def self.build_publish_vulnerabilities_option(name:, discovery_conn_id:)
      step1 = Step.new(service_name: ServiceNames::NEXPOSE, type_name: StepNames::NEW_ASSET_VULN)
      step2 = Step.new(service_name: ServiceNames::DXL, type_name: StepNames::PUBLISH_VULN_INT_TYPE, previous_type_name: step1.type_name)
                  .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, discovery_conn_id)
      IntegrationOption.new(name: name, steps: [step1, step2])
    end
  end
end
