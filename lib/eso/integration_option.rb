module Eso

  module IntegrationOptionNames
    IMPORT_AD_ASSETS = 'import_ad_assets'
    IMPORT_EPO_ASSETS = 'import_epo_assets'
    SYNC_AZURE_ASSETS = 'sync_azure_assets'
    SYNC_AZURE_ASSETS_WITH_TAGS = 'sync_azure_assets_with_tags'
  end

  # IntegrationOptionTypes is a way to categorize what various Integration Options do.
  module IntegrationOptionTypes
    # The IMPORT_TO_SITE Array tracks Integration Options which load Assets into a Site.
    IMPORT_TO_SITE = [
        IntegrationOptionNames::IMPORT_AD_ASSETS,
        IntegrationOptionNames::IMPORT_EPO_ASSETS,
        IntegrationOptionNames::SYNC_AZURE_ASSETS,
        IntegrationOptionNames::SYNC_AZURE_ASSETS_WITH_TAGS
    ]
  end

  class IntegrationOption
    attr_accessor :name
    attr_accessor :steps
    attr_accessor :id

    def initialize(id: nil, name:, steps: [])
      @id = id
      @name = name
      @steps = steps
    end

    def site_id=(site_id)
      # As of now, the site is always in the last Step of the IntegrationOption. Might change.
      @steps.last.add_property(StepConfiguration::ConfigParamProperties::SITE_ID, site_id)
    end

    def site_id
      # As of now, the site is always in the last Step of the IntegrationOption. Might change.
      @steps.last.site_id
    end

    # Return this object and the associated steps in a digestible JSON format.
    #
    # @return [String] JSON interpretation of this workflow.
    #
    def to_json
      # Convert Object to Hash
      hash = self.to_hash

      # Grab the Step objects and convert to Hashes
      steps = hash['steps']
      hashified_steps = []
      steps.each {|step| hashified_steps << step.to_hash}
      hash['steps'] = hashified_steps

      # Convert Hash to JSON
      hash.to_json
    end

    # Return this object as a Hash. The corresponding Steps will still be objects.
    #
    # @return [Hash] Hash interpretation of this IntegrationOption.
    def to_hash
      hash = {}
      instance_variables.each {|var| hash[var.to_s.delete("@")] = instance_variable_get(var)}
      hash
    end

    # Load a Hash of an IntegrationOption into an actual IntegrationOption. Probably didn't need to
    # break out separately, but might be useful
    #
    # @param [Hash] raw_integration_option is a Hash representation of an IntegrationOption
    # @return [IntegrationOption] The IntegrationOption version of the Hash
    def self.load(raw_integration_option)
      integration_option = IntegrationOption.new(id: raw_integration_option[:id], name: raw_integration_option[:name])
      steps = raw_integration_option[:steps]
      steps.each do |step|
        step_config = step[:stepConfiguration]
        integration_option.steps << Step.new(uuid: step[:uuid],
                                             service_name: step[:serviceName],
                                             type_name: step_config[:typeName],
                                             previous_type_name: step_config[:previousTypeName],
                                             configuration_params: step_config[:configurationParams])
      end
      integration_option
    end
  end
end
