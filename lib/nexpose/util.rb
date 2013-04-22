module Nexpose
  module Sanitize
    def replace_entities(str)
      str.to_s.gsub(/&/, '&amp;').gsub(/'/, '&apos;').gsub(/"/, '&quot;').gsub(/</, '&lt;').gsub(/>/, '&gt;')
    end
  end

  module XMLUtils

    def parse_xml(xml)
      ::REXML::Document.new(xml.to_s)
    end

    def make_xml(name, opts={}, data='', append_session_id=true)
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
  end
end
