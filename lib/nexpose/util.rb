module Nexpose

  module Sanitize
    def replace_entities(str)
      str.to_s.gsub(/&/, '&amp;').gsub(/'/, '&apos;').gsub(/"/, '&quot;').gsub(/</, '&lt;').gsub(/>/, '&gt;')
    end
  end

  module HTMLUtils
    def parse_html(html)
      Nokogiri::HTML(html, nil, 'UTF-8')
    end
  end

  module XMLUtils

    def parse_xml(xml)
      ::REXML::Document.new(xml.to_s)
    end

    def make_xml(name, opts = {}, data = '', append_session_id = true)
      xml = REXML::Element.new(name)
      if @session_id and append_session_id
        xml.attributes['session-id'] = @session_id
      end

      opts.keys.each do |k|
        if opts[k] != nil
          xml.attributes[k] = "#{opts[k]}"
        end
      end

      xml.text = data

      xml
    end

    # Check a typical Nexpose XML response for success.
    # Typically, the root element has a 'success' attribute, and its value is
    # '1' if the call succeeded.
    #
    def self.success?(xml_string)
      xml = ::REXML::Document.new(xml_string.to_s)
      success = ::REXML::XPath.first(xml, '//@success')
      !success.nil? && success.value.to_i == 1
    end
  end

  # Function module for dealing with String to HostName|IPRange conversions.
  #
  module HostOrIP
    module_function

    # Convert a host or IP address to the corresponding HostName or IPRange
    # class.
    #
    # If the String cannot be converted, it will raise an error.
    #
    # @param [String] asset String representation of an IP or host name.
    # @return [IPRange|HostName] Valid class, if it can be converted.
    #
    def convert(asset)
      begin
        # Use IPAddr construtor validation to see if it's an IP.
        IPAddr.new(asset)
        IPRange.new(asset)
      rescue ArgumentError => e
        if e.message == 'invalid address'
          HostName.new(asset)
        else
          raise "Unable to parse asset: '#{asset}'. #{e.message}"
        end
      end
    end
  end
end
