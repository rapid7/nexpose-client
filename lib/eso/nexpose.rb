require 'nexpose'

module Eso
  module ServiceNames
    ACTIVE_DIRECTORY = 'active-directory'
    AWS = 'amazon-web-services'
    AZURE = 'azure'
    DXL = 'dxl'
    EPO = 'epo'
    NEXPOSE = 'nexpose'
  end

  module StepNames
    ADD_TO_SITE = 'add-to-site'
    ADD_VULN_AND_SCAN = 'add-vulnerabilities-to-site-and-scan'
    DISCOVER_ACTIVE_DIRECTORY = 'discover-ad-assets'
    DISCOVER_AWS_ASSETS = 'discover-aws-assets'
    DISCOVER_AZURE_ASSETS = 'discover-azure-assets'
    DISCOVER_EPO = 'discover-epo-assets'
    DISCOVER_KNOWN = 'discover-known-assets'
    DISCOVER_NEW = 'discover-new-assets'
    DISCOVERY_CONFIG_METADATA = 'discoveryConfigMetadata'
    EMPTY = ''
    FILE_REPUTATION_TRIGGER = 'tie-file-reputation-trigger'
    IMPORT_EXTERNAL = 'import-external-assets'
    NEW_ASSET_VULN = 'new-asset-vulnerability'
    NEW_VULN = 'new-vulnerabilities'
    PUBLISH_VULN_INT_TYPE = 'publish-vulnerability-integration-type'
    PUSH_RISK_SCORE = 'push-risk-score'
    RISK_SCORE_UPDATED = 'risk-score-updated'
    SCAN = 'scan'
    SCAN_IN_SITE = 'scan-in-site'
    SYNC_EXTERNAL = 'sync-external-assets'
    TAG = 'tag'
    VERIFY_AWS_ASSETS = 'verify-aws-targets'
    VERIFY_EXTERNAL_TARGETS = 'verify-external-targets'
    VULN_DETAILS = 'vulnerability-details'
    VULN_DETAILS_REQUEST = 'vulnerability-details-request'
  end

  module Values
    ARRAY = 'Array'
    BOOLEAN = 'Boolean'
    INTEGER = 'Integer'
    OBJECT = 'Object'
    STRING = 'String'
  end

  module StepConfigTypes
    DISCOVERY_CONFIG = [StepNames::DISCOVER_ACTIVE_DIRECTORY,
                        StepNames::DISCOVER_AWS_ASSETS,
                        StepNames::DISCOVER_AZURE_ASSETS,
                        StepNames::DISCOVER_EPO,
                        StepNames::DISCOVER_KNOWN,
                        StepNames::DISCOVER_NEW,
                        StepNames::FILE_REPUTATION_TRIGGER,
                        StepNames::PUBLISH_VULN_INT_TYPE,
                        StepNames::PUSH_RISK_SCORE,
                        StepNames::VULN_DETAILS_REQUEST]
    EMPTY = [StepNames::NEW_ASSET_VULN,
             StepNames::NEW_VULN,
             StepNames::RISK_SCORE_UPDATED,
             StepNames::VULN_DETAILS]
    SITE = [StepNames::ADD_TO_SITE,
            StepNames::ADD_VULN_AND_SCAN,
            StepNames::IMPORT_EXTERNAL,
            StepNames::SCAN,
            StepNames::SCAN_IN_SITE,
            StepNames::SYNC_EXTERNAL]
    TAG = [StepNames::TAG]
    VERIFY = [StepNames::DISCOVER_AWS_ASSETS]
  end

  module Filters
    CVSS_SCORE = 'CVSS_SCORE'
    DHCP_HOST_NAME = 'DHCP_HOST_NAME'
    HOURS_SINCE_LAST_SCAN= 'HOURS_SINCE_LAST_SCAN'
    HOURS_SINCE_LAST_SCAN_ITEM = 'HOURS_SINCE_LAST_SCAN_ITEM'
    IP_ADDRESS = 'IP_ADDRESS'
    IP_RANGE = 'IP_RANGE'
    MAC_ADDRESS = 'MAC_ADDRESS'
    OPEN_PORT = 'OPEN_PORT'
    RISK_SCORE = 'RISK_SCORE'
    SERVICE_NAME = 'SERVICE_NAME'
  end

  module Nexpose
    def self.create_discovery_workflow(conductor:, name:, step1_type:, step1_param: nil, step2_type:, step2_param:)
      step1 = self.send("create_#{step1_type.to_s.gsub(/-/, "_")}_step", id: step1_param)
      step2 = self.send("create_#{step2_type.to_s.gsub(/-/, "_")}_step", id: step2_param)
      step2.previous_type_name = step1.type_name
      conductor.create_workflow(name: name, steps: [step1, step2])
    end

    def self.create_scan_new_vuln_workflow(conductor:, name:, filters:, site_id:)
      step1 = self.create_new_vuln_step(workflow: nil, filters: filters, previous_type_name: StepNames::EMPTY)
      step2 = self.create_add_vuln_and_scan_step(id: site_id)
      step2.previous_type_name = step1.type_name
      conductor.create_workflow(name: name, steps: [step1, step2])
    end

    def self.create_file_trigger_workflow(conductor:, name:, step1_param:, step2_param:)
      step1 = self.create_file_reputation_step(workflow: nil, id: step1_param)
      step2 = self.create_tag_step(workflow: nil, id: step2_param)
      step2.previous_type_name = step1.type_name
      conductor.create_workflow(name: name, steps: [step1, step2])
    end

    def self.create_scan_in_site_step(workflow: nil, id:, previous_type_name: StepNames::EMPTY)
      Step.new(workflow: workflow,
               service_name: ServiceNames::NEXPOSE,
               type_name: StepNames::SCAN_IN_SITE,
               previous_type_name: previous_type_name)
          .add_property(StepConfiguration::ConfigParamProperties::SITE_ID, id)
    end

    def self.create_file_reputation_step(workflow: nil, id:)
      Step.new(workflow: workflow,
               service_name: ServiceNames::DXL,
               type_name: StepNames::FILE_REPUTATION_TRIGGER,
               previous_type_name: nil)
          .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, id)
    end

    def self.create_discover_new_assets_step(workflow: nil, id:, previous_type_name: StepNames::EMPTY)
      Step.new(workflow: workflow,
               service_name: ServiceNames::NEXPOSE,
               type_name: StepNames::DISCOVER_NEW,
               previous_type_name: previous_type_name)
          .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, id)
    end

    def self.create_discover_known_assets_step(workflow: nil, id:, previous_type_name: StepNames::EMPTY)
      step = Step.new(workflow: workflow,
               service_name: ServiceNames::NEXPOSE,
               type_name: StepNames::DISCOVER_KNOWN,
               previous_type_name: previous_type_name)
                 .add_property(StepConfiguration::ConfigParamProperties::DISCOVERY_CONFIG_ID, id)
      config_params = step.configuration_params
      config_params[:HOURS_SINCE_LAST_SCAN] = {
          :valueClass => Values::ARRAY,
          :items => [
              {
                  :valueClass => Values::OBJECT,
                  :objectType => Filters::HOURS_SINCE_LAST_SCAN_ITEM,
                  :properties => {
                      :operator => {
                          :valueClass => Values::STRING,
                          :value => ::Nexpose::Search::Operator::GREATER_THAN
                      },
                      :operand1 => {
                          :valueClass  => Values::STRING,
                          :value => '1'
                      }
                  }
              }
          ]
      }
      step.configuration_params = config_params
      step
    end

    def self.create_new_vuln_step(workflow: nil, filters:, previous_type_name: StepNames::EMPTY)
      # The filter definitions on the server are not standard at this point so that is why it is necessary to hard code this
      # Opening a defect to fix the consistency on these on the backend so we can use the add_filter function in the automation
      step = Step.new(workflow: workflow,
               service_name: ServiceNames::NEXPOSE,
               type_name: StepNames::NEW_VULN,
               previous_type_name: previous_type_name)

      filters.each { |filter| step.add_filter(filter) }
      step
    end

    def self.create_add_vuln_and_scan_step(workflow: nil, id:, previous_type_name: StepNames::EMPTY)
      Step.new(workflow: workflow,
               service_name: ServiceNames::NEXPOSE,
               type_name: StepNames::ADD_VULN_AND_SCAN,
               previous_type_name: previous_type_name)
          .add_property(StepConfiguration::ConfigParamProperties::SITE_ID, id)
    end

    def self.create_add_to_site_step(workflow: nil, id:, previous_type_name: StepNames::EMPTY)
       Step.new(workflow: workflow,
               service_name: ServiceNames::NEXPOSE,
               type_name: StepNames::ADD_TO_SITE,
               previous_type_name: previous_type_name)
           .add_property(StepConfiguration::ConfigParamProperties::SITE_ID, id)
    end

    def self.create_scan_step(workflow: nil, id:, previous_type_name: StepNames::EMPTY)
     Step.new(workflow: workflow,
              service_name: ServiceNames::NEXPOSE,
              type_name: StepNames::SCAN,
              previous_type_name: previous_type_name)
         .add_property(StepConfiguration::ConfigParamProperties::SITE_ID, id)
    end

    def self.create_tag_step(workflow: nil, id:, previous_type_name: StepNames::EMPTY)
       Step.new(workflow: workflow,
                service_name: ServiceNames::NEXPOSE,
                type_name: StepNames::TAG,
                previous_type_name: previous_type_name)
           .add_property(StepConfiguration::ConfigParamProperties::TAG_ID, id)
    end

    def self.get_discover_step(workflow: )
      workflow.get_step(StepNames::DISCOVER_NEW) || workflow.get_step(StepNames::DISCOVER_KNOWN)
    end
  end
end

