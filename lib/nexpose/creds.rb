module Nexpose
	# === Description
	# Object that represents administrative credentials to be used during a scan. When retrived from an existing site configuration the credentials will be returned as a security blob and can only be passed back as is during a Site Save operation. This object can only be used to create a new set of credentials.
	#
	class AdminCredentials
		# Security blob for an existing set of credentials
		attr_reader :securityblob
		# Designates if this object contains user defined credentials or a security blob
		attr_reader :isblob
		# The service for these credentials. Can be All.
		attr_reader :service
		# The host for these credentials. Can be Any.
		attr_reader :host
		# The port on which to use these credentials.
		attr_reader :port
		# The user id or username
		attr_reader :userid
		# The password
		attr_reader :password
		# The realm for these credentials
		attr_reader :realm


		def initialize(isblob = false)
			@isblob = isblob
		end

		# Sets the credentials information for this object.
		def setCredentials(service, host, port, userid, password, realm)
			@isblob = false
			@securityblob = nil
			@service = service
			@host = host
			@port = port
			@userid = userid
			@password = password
			@realm = realm
		end

		# TODO: add description
		def setService(service)
			@service = service
		end

		def setHost(host)
			@host = host
		end

		# TODO: add description
		def setBlob(securityblob)
			@isblob = true
			@securityblob = securityblob
		end

		include Sanitize

		def to_xml
			xml = ''
			xml << '<adminCredentials'
			xml << %Q{ service="#{replace_entities(service)}"} if (service)
			xml << %Q{ userid="#{replace_entities(userid)}"} if (userid)
			xml << %Q{ password="#{replace_entities(password)}"} if (password)
			xml << %Q{ realm="#{replace_entities(realm)}"} if (realm)
			xml << %Q{ host="#{replace_entities(host)}"} if (host)
			xml << %Q{ port="#{replace_entities(port)}"} if (port)
			xml << '>'
			xml << replace_entities(securityblob) if (isblob)
			xml << '</adminCredentials>'

			xml
		end
	end
end