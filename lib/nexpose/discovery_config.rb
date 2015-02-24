module Nexpose

  # Object that represents discovery config of dynamic site.
  class DiscoveryConfig < APIObject

    # Unique identifier of the discovery config on the Nexpose console. [required]
    attr_accessor :id
    # The name [optional]
    attr_accessor :name
    # connection type of dynamic site [optional]
    attr_accessor :connection_type

    # get discovery config object from hash
    def self.from_hash(hash)
      config = new
      hash.each do |k, v|
        config.instance_variable_set("@#{k}", v)
      end
      config
    end

    def to_json
      JSON.generate(to_h)
    end

    def to_h
      { id: id,
        name: name,
        connection_type: connection_type
      }
    end

    def <=>(other)
      c = id <=> other.id
      return c unless c == 0
      c = name <=> other.name
      return c unless c == 0
      connection_type <=> other.connection_type
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      id.eql?(other.id) &&
      name.eql?(other.name) &&
      connection_type.eql?(other.connection_type)
    end

    # Override of filter criterion to account for proper JSON naming.
    #
    class Criterion < Nexpose::Criterion
      # Convert to Hash, which can be converted to JSON for API calls.
      def to_h
        { operator: operator,
          values: Array(value),
          field_name: field }
      end

      # Create a Criterion object from a JSON-derived Hash.
      #
      # @param [Hash] json JSON-derived Hash of a Criterion object.
      # @return [Criterion] Parsed object.
      #
      def self.parseHash(hash)
        Criterion.new(hash[:field_name],
                      hash[:operator],
                      hash[:values])
      end
    end

    # Override of filter criteria to account for different parsing from JSON.
    #
    class Criteria < Nexpose::Criteria
      # Create a Criteria object from a Hash.
      #
      # @param [Hash] Hash of a Criteria object.
      # @return [Criteria] Parsed object.
      #
      def self.parseHash(hash)
        # The call returns empty JSON, so default to 'AND' if not present.
        operator = hash[:operator] || 'AND'
        ret = Criteria.new([], operator)
        hash[:criteria].each do |c|
          ret.criteria << Criterion.parseHash(c)
        end
        ret
      end
    end
  end
end
