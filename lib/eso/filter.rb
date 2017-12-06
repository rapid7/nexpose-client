module Eso
  class Filter
    # These are defined in Eso::Filters which reside in the respective service they are related to.
    attr_accessor :type

    # These are the individual filter items
    attr_accessor :filter_items

    # Constructor for Filter.
    #
    # @param [String] type The type of filter this is. They are based on the service this filter exists in. These are defined in Eso::Filters which reside in the respective service they are related to.
    # @param [Array] items Array of filters of this type
    # @return [Eso::Filter] The newly created filter object
    #
    def initialize(type:, items: [])
      @type = type
      @filter_items = items
     end

    # Append a filter_item later
    def <<(filter_item)
      @filter_items << filter_item
    end

    def to_json
      self.to_hash.to_json
    end

    def to_hash
      hash = {}
      hash[@type.to_sym] = {
        valueClass: 'Array',
        items: @filter_items.map{|item| item.to_hash}
      }
      hash
    end
    alias_method :to_h, :to_hash

    class FilterItem
      attr_accessor :type
      # Examples are "OR", "IN", "CONTAINS". These should probably be constantized somewhere.
      attr_accessor :operator
      
      # Array containing the values to filter on
      attr_accessor :operands

      def initialize(type:, operator:, operands:)
        @type = "#{type}_ITEM"
        @operator = operator
        process_operands(operands)
      end
      
      def process_operands(operands)
        @operands =
          if ["IS_EMPTY", "IS_NOT_EMPTY"].include? @operator
            nil
          elsif @type == "#{Eso::Filters::IP_ADDRESS}_ITEM" ||
             @type == "#{Eso::Filters::IP_RANGE}_ITEM" ||
             @type == "#{Eso::Filters::OPEN_PORT}_ITEM" ||
             @type == "#{Eso::Filters::RISK_SCORE}_ITEM" ||
             @type == "#{Eso::Filters::CVSS_SCORE}_ITEM"
            operands.first.split('-')
          else
            operands
          end

        if @operands == nil
          return
        end
        @operands.map! do |value|
          # This regex is used to determine if the string is actually a float.
          # http://stackoverflow.com/questions/1034418/determine-if-a-string-is-a-valid-float-value
          if value =~ /^\s*[+-]?((\d+_?)*\d+(\.(\d+_?)*\d+)?|\.(\d+_?)*\d+)(\s*|([eE][+-]?(\d+_?)*\d+)\s*)$/
            if (@type == "#{Eso::Filters::OPEN_PORT}_ITEM")
              value.to_i
            else
              value.to_f
            end
            # If it's not a float, let's see if it's an integer.
          elsif value.to_i.to_s == value
            value.to_i
            # Guess not, so lets keep the original value.
          else
            value
          end
        end
      end
      
      def to_hash
        hash = {
          valueClass: "Object",
          objectType: @type,
          properties: {
            operator: {
              valueClass: "String",
              value: @operator
            }
          }
        }
        # Currently there are no standards that say how many operands a filter can have
        operand_hash = {}
        operand_counter = 1
        unless @operands.nil?
          @operands.each do |operand|
            label = "operand#{operand_counter}".to_sym
          
            # A correct value class is required because Jackson expects it.
            # A Jackson processor for Ruby would probably make this much nicer
            # Also, defaulting to Number is probably a bad idea, but based on current possible values in ESO this works.
            case operand.class.to_s
                
            when "String"
              value_class = "String"
            when "Array"
              value_class = "Array"
            when "Fixnum"
              value_class = "Integer"
            else
              value_class = "Number"
            end
            
            operand_hash[label] = {
              valueClass: value_class,
              value: operand
            }
            operand_counter += 1
          end

          hash[:properties].merge! operand_hash
        end

        hash
      end
    end
  end
end

