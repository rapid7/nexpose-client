module Nexpose
  class Tag

    class Criterion < Nexpose::Criterion

      def to_map
        { 'operator' => operator,
          'values' => Array(value),
          'field_name' => field
        }
      end

      def self.parse(json)
        Criterion.new(json['field_name'],
                      json['operator'],
                      json['values'])
      end

    end

    class Criteria < Nexpose::Criteria

      def initialize(criteria = [], match = 'AND')
        super(criteria, match)
      end

      def to_map
        { 'criteria' => @criteria.map { |c| c.to_map },
          'operator' => @match
        }
      end

      def self.parse(json)
        ret = Criteria.new([], json['operator'])
        json['criteria'].each do |c|
          ret.criteria << Criterion.parse(c)
        end
        ret
      end

    end
  end
end


