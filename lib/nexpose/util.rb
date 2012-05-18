module Nexpose
	module Sanitize
		def replace_entities(str)
			ret = str.dup
			ret.gsub!(/&/, "&amp;")
			ret.gsub!(/'/, "&apos;")
			ret.gsub!(/"/, "&quot;")
			ret.gsub!(/</, "&lt;")
			ret.gsub!(/>/, "&gt;")
			ret
		end
	end

	module XMLUtils
		def parse_xml(xml)
			::REXML::Document.new(xml.to_s)
		end

		def make_xml(name, opts={}, data='', append_session_id=true)
			xml = REXML::Element.new(name)
			if (@session_id and append_session_id)
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
