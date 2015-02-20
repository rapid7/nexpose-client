module Nexpose
  module JsonSerializer
    @@namespace = 'Nexpose'

    def deserialize(data)
      data.each do |key, value|
        property = value

        if value.respond_to? :each
          obj = resolve_type(key)

          unless obj.nil?
            if value.is_a?(Array)
              property = value.map { |element|  ((value.respond_to? :each) ? obj.method(:new).call.deserialize(element): element) }
            else
              property = obj.method(:new).call.deserialize(value)
            end
          end
        elsif value.is_a?(String) && value.match(/^\d{8}T\d{6}\.\d{3}/)
          property = ISO8601.to_time(value)
        end

        instance_variable_set("@#{key}", property)
      end
      self
    end

    private

    def resolve_type(field)
      class_name = normalize_field(field)

      if Object.const_get(@@namespace).const_defined?(class_name)
        clazz = Object.const_get(@@namespace).const_get(class_name)

        if clazz.included_modules.include? JsonSerializer
          return clazz
        end
      end
    end

    def normalize_field(field)
      str = field.to_s.split('_').map(&:capitalize!).join
      str = 'Vulnerability' if str == 'Vulnerabilities'
      str.chop! if str.end_with?('s')
      str
    end
  end
end