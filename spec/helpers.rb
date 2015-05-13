module Helpers
  # (RE)XML related helper methods.
  module XML
    # Converts `REXML::Attributes` into a `Hash`.
    #
    # @param [REXML::Attributes] attributes The attributes to convert
    #   into a Hash.
    # @return [Hash] the attribute keys mapped to the attribute values
    def attributes_to_hash(attributes)
      Hash[attributes.to_enum.to_a]
    end
  end

  module HashKeys
    module_function

    def get_all_keys(object)
      if object.is_a? Hash
        (object.keys + get_all_keys(object.values)).flatten.uniq
      elsif object.is_a? Array
        object.collect{|value| get_all_keys value}
      else
        []
      end
    end

  end
end
