module Eso
  class StepConfiguration
    attr_accessor :typeName, :previousTypeName, :configurationParams, :workflowID

    module ConfigParamProperties
      DISCOVERY_CONFIG_ID = 'discoveryConfigID'
      EXCLUDE_ASSETS_WITH_TAGS= 'excludeAssetsWithTags'
      IMPORT_TAGS = 'importTags'
      ONLY_IMPORT_THESE_TAGS = 'onlyImportTheseTags'
      SITE_ID = 'siteID'
      TAG_ID = 'tagID'
    end

    module ConfigParamPropertyTypes
      BOOLEAN = [ConfigParamProperties::IMPORT_TAGS]
      INTEGER = [ConfigParamProperties::DISCOVERY_CONFIG_ID,
                 ConfigParamProperties::SITE_ID,
                 ConfigParamProperties::TAG_ID]
      STRING = [ConfigParamProperties::EXCLUDE_ASSETS_WITH_TAGS,
                ConfigParamProperties::ONLY_IMPORT_THESE_TAGS]
    end

    def initialize (typeName, previousTypeName, configurationParams=nil, workflowID=nil)
      @typeName = typeName
      @previousTypeName = previousTypeName
      @configurationParams = configurationParams ? configurationParams : {
          :valueClass => Values::OBJECT,
          :objectType => 'params',
          :properties => {}}
      @workflowID = workflowID if workflowID
    end

    # This adds the specified property to this StepConfiguration.configurationParams.properties Hash
    #
    # @param [String] name The name of the property to add, which should be one of ConfigParamProperties
    # @param [Object] value The value of the property to add, which should already be in the appropriate format (Eso::Values)
    # @return [StepConfiguration] Returns this object for chaining.
    def add_property(name, value)
      @configurationParams[:properties][name] =
          case name
            when *ConfigParamPropertyTypes::BOOLEAN
              {
                  valueClass: Values::BOOLEAN,
                  value: value
              }
            when *ConfigParamPropertyTypes::INTEGER
              {
                  valueClass: Values::INTEGER,
                  value: value
              }
            when *ConfigParamPropertyTypes::STRING
              {
                  valueClass: Values::STRING,
                  value: value
              }
            else
              raise ArgumentError, "Invalid StepConfiguration ConfigurationParameter Property name: #{name}. " +
                  'Should be one of StepConfiguration::ConfigParamProperties'
          end
      self
    end

    def to_h
      hash = {
          :typeName => @typeName,
          :previousTypeName => @previousTypeName,
          :configurationParams => @configurationParams
      }
      hash['workflowID'] = @workflowID if @workflowID
      hash
    end
  end
end
