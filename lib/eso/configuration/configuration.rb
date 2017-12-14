module Eso
  # This class represents the Configuration that is sent to the server for new
  # style Discovery Connections.
  class Configuration
    attr_accessor :service_name, :config_name, :config_id, :properties

    def initialize(service_name:, config_name:, properties:[], config_id:)
      @service_name = service_name
      @config_name = config_name
      @properties = properties
      @config_id = config_id
    end

    # Convert the Configuration to a JSON string for sending to Nexpose
    #
    # @return [String] A JSON String representation of the Configuration
    def to_json
      self.to_hash.to_json
    end

    # Convert the Configuration to a Hash
    #
    # @return [Hash] A Hash representation of the Configuration
    def to_hash
      hash = {:configId => @config_id,
              :serviceName => @service_name,
              :configName => @config_name,
              :configurationAttributes => {:valueClass => 'Object',
                                           :objectType => 'service_configuration',
                                           :properties => []}}
      properties.each {|prop| hash[:configurationAttributes][:properties] << prop.to_hash}
    end

    # Retrieve a Configuration attribute property value given the name of the property
    #
    # @param [String] name The name of the property to retrieve
    # @return [String] The value of the property
    def property(name)
      properties.find{|attr| attr.property == name}.value
    end

    # Update a Configuration attribute property value given the name of the property
    #
    # @param [String] name The name of the property to update
    # @param [String] value The value of the property to update
    # @return [String] The value of the property
    def update_property(name, value)
      properties.find{|attr| attr.property == name}.value = value
    end

    # Load a Configuration object from a Hash
    #
    # @param [Hash] hash The Hash containing the Configuration object
    # @return [Configuration] The Configuration object which was in the Hash
    def self.load(hash)
      configuration = self.new(service_name: hash[:serviceName],
                               config_name: hash[:configName],
                               config_id: hash[:configID])
      hash[:configurationAttributes][:properties].each do |prop|
        configuration.properties << ConfigurationAttribute.load(prop)
      end
      configuration
    end
  end

  # The ConfigurationAttribute is a property of the Configuration
  class ConfigurationAttribute
    attr_accessor :property, :value_class, :value

    def initialize(property, value_class, value)
      @property = property
      @value_class = value_class
      @value = value
    end

    # Convert the ConfigurationAttribute to a JSON string for sending to Nexpose
    #
    # @return [String] A JSON String representation of the ConfigurationAttribute
    def to_json
      self.to_hash.to_json
    end

    # Convert the ConfigurationAttribute to a Hash
    #
    # @return [Hash] A Hash representation of the ConfigurationAttribute
    def to_hash
      prop = @property.to_sym
      hash = {prop => {}}
      hash[prop]['valueClass'] = @value_class
      hash[prop]['value'] = @value
    end

    # Load a ConfigurationAttribute object from an Array
    #
    # @param [Array] array The Array containing the ConfigurationAttribute object
    # @return [ConfigurationAttribute] The ConfigurationAttribute object which was in the Array
    def self.load(array)
      property = array.first
      value_class = array.last['valueClass']
      value =
          if value_class == 'Array'
            array.last['items'].map{|item| item['value']}
          else
            array.last['value']
          end
      self.new(property, value_class, value)
    end
  end
end
