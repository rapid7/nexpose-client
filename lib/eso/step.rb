module Eso
  # Object representation of a step, which are attributes of Workflows and Integration Options
  #
  class Step
    # UUID of this step. This is generated on creation on the server.
    attr_accessor :uuid

    # Type of this step. Should be one of Eso::ServiceNames
    attr_accessor :serviceName

    # The configuration for this step.
    attr_accessor :stepConfiguration

    # Constructor for Step.
    #
    # @param [String] uuid UUID of this Step. This is created on the server side upon creation through the API.
    # @param [String] service_name The name of step this is.
    # @param [Workflow] workflow The workflow this step belongs to.
    # @param [Hash] configuration_params Hash of the parameters for this step.
    #
    def initialize(uuid: nil, service_name:, workflow: nil, type_name:, previous_type_name: StepNames::EMPTY, configuration_params: nil)
      @uuid = uuid if uuid
      @serviceName = service_name
      @stepConfiguration = StepConfiguration.new(type_name, previous_type_name)
      @stepConfiguration.configurationParams = configuration_params if configuration_params
      @stepConfiguration.workflowID = workflow.id if workflow
    end

    # Return the configuration parameters for this step.
    #
    # @return [Hash] Hash of the configuration parameters for this step.
    #
    def configuration_params
      @stepConfiguration.configurationParams
    end

    # Set the the configuration parameters for this step.
    #
    # @param [Hash] config_params of the new configuration parameters you would like to set.
    # @return [Hash] Hash of the updated configuration parameters for this step.
    #
    def configuration_params=(config_params)
      @stepConfiguration.configurationParams = config_params
    end

    # Return the type name for this step.
    #
    # @return [String] The currently configured type name.
    #
    def type_name
      @stepConfiguration.typeName
    end

    # Set the type name for this step.
    #
    # @param [String] The new type_name that you would like to set this to. See Eso::StepNames for valid names.
    # @return [String] The newly set type name.
    #
    def type_name=(wf_action_name)
      @stepConfiguration.typeName = wf_action_name
    end

    # Return the previous type name for this step.
    #
    # @return [String] The previous type name for this step.
    #
    def previous_type_name
      @stepConfiguration.previousTypeName
    end

    # Set the previous type name for this step.
    #
    # @param [String] The new previous type name that you would like to set. See Eso::StepNames for valid names.
    # @return [String] Hash of the configuration parameters for this step.
    #
    def previous_type_name=(action_name)
      @stepConfiguration.previousTypeName = action_name
    end

    # Return the properties of this step.
    #
    # @return [Hash{}] Hash of the properties for this step.
    #
    def properties
      @stepConfiguration.configurationParams[:properties]
    end

    # Set the properties of this step.
    #
    # @param [Hash] The new properties to set for this step.
    # @return [Hash] Hash of the newly configured properties for this step.
    #
    def properties=(new_properties)
      @stepConfiguration.configurationParams[:properties] = new_properties
    end

    # Determine the siteID of this step, if it exists
    #
    # @return [String|nil] The String siteID value or nil if no siteID
    def site_id
      if @stepConfiguration.configurationParams[:properties][:siteID]
        @stepConfiguration.configurationParams[:properties][:siteID][:value]
      end
    end

    # Returns all configured filters for this step.
    #
    # @return [Array] An array of the currently configured filters for this step, each represented as a hash.
    #
    def filters
      rv = {}
      self.properties.each_pair do |key, value|
        if value[:properties]
          rv[key] = value if value[:properties].has_key?(:operators)
        end
      end
      rv
    end

    # Convenience method which calls the #add_property method of the @stepConfiguration, but returns the Step
    #
    # @return [Step] Returns this Step for chaining
    def add_property(name, value)
      @stepConfiguration.add_property(name, value)
      self
    end

    # Convenience method which calls the #add_property method of the @stepConfiguration, but returns the Step
    #
    # @return [Step] Returns this Step for chaining
    def update_property(name, value)
      @stepConfiguration.add_property(name, value)
      self
    end

    # Add the specified filter to this step. The filter is converted to a hash and saved as such instead of being saved as a ESO::Filter object.
    #
    # @param [Filter] filter The filter to add to this step.
    #
    def add_filter(filter)
      @stepConfiguration.configurationParams[:properties].merge! filter.to_hash
    end

    # Return this step in a JSON digestible format.
    #
    # @return [String] JSON interpretation of this step.
    #
    def to_json
      self.to_hash.to_json
    end

    # Return this step as a hash.
    #
    # @return [Hash] Hash interpretation of this step.
    #
    def to_hash
      hash = {}
      instance_variables.each do |var|
        value = instance_variable_get(var)
        value = value.to_h if value.respond_to?('to_h')
        hash[var.to_s.delete('@')] = value
      end
      hash
    end
  end
end
