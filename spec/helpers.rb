module Helpers
  # (RE)XML related helper methods.
  module XML
    # Converts `REXML::Attributes` into a `Hash`.
    #
    # @param [REXML::Attributes] attributes The attributes to convert
    #   into a Hash.
    # @return [Hash] the attribute keys mapped to the attribute values
    def attributes_to_hash(attributes)
      attributes.to_enum.to_h
    end
  end
end
