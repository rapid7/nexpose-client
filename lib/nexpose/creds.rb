module Nexpose
   include Sanitize

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
      # When using httpheaders, this represents the set of headers to pass
      # with the authentication request.
      attr_reader :headers
      # When using htmlforms, this represents the tho form to pass the
      # authentication request to.
      attr_reader :html_forms

      def initialize(isblob = false)
         @isblob = isblob
	 @html_forms = Array.new()
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

      # Add Headers to credentials for httpheaders.
      def setHeaders(headers)
         @headers = headers
      end

      def setHTMLForms(html_forms)
	  @html_forms = html_forms
      end

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
         xml << @headers.to_xml() if @headers
         xml << @html_forms.to_xml() if @html_forms
         xml << '</adminCredentials>'

         xml
      end
   end

   # Object that represents Header name-value pairs, associated with Web Session Authentication.
   class Header
      # Name, one per Header
      attr_reader :name
      # Value, one per Header
      attr_reader :value

      # Construct with name value pair
      def initialize(name, value)
         @name = name
         @value = value
      end

      def to_xml
         xml = ''
         xml << '<Header'
         xml << %Q{ name="#{replace_entities(name)}"} if (name)
         xml << %Q{ value="#{replace_entities(value)}"} if (value)
         xml << '/>'
         xml
      end
   end

   # Object that represents Headers, associated with Web Session Authentication.
   class Headers
      # A regular expression used to match against the response to identify authentication failures.
      attr_reader :soft403
      # Base URL of the application for which the form authentication applies.
      attr_reader :webapproot
      # When using httpheaders, this represents the set of headers to pass with the authentication request.
      attr_reader :headers

      def initialize(webapproot, soft403)
         @headers = []
         @webapproot = webapproot
         @soft403 = soft403
      end

      def addHeader(header)
         @headers.push(header)
      end


      def to_xml
         xml = ''
         xml << '<Headers'
         xml << %Q{ soft403="#{replace_entities(soft403)}"} if (soft403)
         xml << %Q{ webapproot="#{replace_entities(webapproot)}"} if (webapproot)
         xml << '>'
         @headers.each do |header|
            xml << header.to_xml
         end
         xml << '</Headers>'
         xml
      end
   end

   # When using htmlform, this represents the login form information.
   class Field
      # The name of the HTML field (form parameter).
      attr_reader :name
      # The value of the HTML field (form parameter).
      attr_reader :value
      # The type of the HTML field (form parameter).
      attr_reader :type
      # Is the HTML field (form parameter) dynamically generated? If so,
      # the login page is requested and the value of the field is extracted
      # from the response.
      attr_reader :dynamic
      # If the HTML field (form parameter) is a radio button, checkbox or select
      # field, this flag determines if the field should be checked (selected).
      attr_reader :checked

      def initialize(name, value, type, dynamic, checked)
	  @name = name
	  @value = value
	  @type = type
	  @dynamic = dynamic
	  @checked = checked
      end

      def to_xml
	  xml = ''
	  xml << '<Field'
	  xml << %Q{ name="#{replace_entities(name)}"} if (name)
	  xml << %Q{ value="#{replace_entities(value)}"} if (value)
	  xml << %Q{ type="#{replace_entities(type)}"} if (type)
	  xml << %Q{ dynamic="#{replace_entities(dynamic)}"} if (dynamic)
	  xml << %Q{ checked="#{replace_entities(checked)}"} if (checked)
	  xml << '>'
	  xml << '</Field>'
      end
   end

   # When using htmlform, this represents the login form information.
   class HTMLForm
      # The name of the form being submitted.
      attr_reader :name
      # The HTTP action (URL) through which to submit the login form.
      attr_reader :action
      # The HTTP request method with which to submit the form.
      attr_reader :method
      # The HTTP encoding type with which to submit the form.
      attr_reader :enctype
      # The fields in the HTML Form
      attr_reader :fields

      def initialize(name, action, method, enctype)
	  @name = name
	  @action = action
	  @method = method
	  @enctype = enctype
	  @fields = Array.new()
      end

      def add_field(field)
	  @fields << field
      end

      def to_xml
	  xml = ''
	  xml << '<HTMLForm'
	  xml << %Q{ name="#{replace_entities(name)}"} if (name)
	  xml << %Q{ action="#{replace_entities(action)}"} if (action)
	  xml << %Q{ method="#{replace_entities(method)}"} if (method)
	  xml << %Q{ enctype="#{replace_entities(enctype)}"} if (enctype)
	  xml << '>'
	  fields.each() do |field|
	      xml << field.to_xml
	  end
	  xml << '</HTMLForm>'
      end
   end

   # When using htmlform, this represents the login form information.
   class HTMLForms
      # The URL of the login page containing the login form.
      attr_reader :parentpage
      # A regular expression used to match against the response to identify
      # authentication failures.
      attr_reader :soft403
      # Base URL of the application for which the form authentication applies.
      attr_reader :webapproot
      # The forms to authenticate with
      attr_reader :html_forms

      def initialize(parentpage, soft403, webapproot)
	  @parentpage = parentpage
	  @soft403 = soft403
	  @webapproot = webapproot
	  @html_forms = Array.new()
      end

      def add_html_form(html_form)
	  @html_forms << html_form
      end

      def to_xml
	  xml = ''
	  xml << '<HTMLForms'
	  xml << %Q{ parentpage="#{replace_entities(parentpage)}"} if (parentpage)
	  xml << %Q{ soft403="#{replace_entities(soft403)}"} if (soft403)
	  xml << %Q{ webapproot="#{replace_entities(webapproot)}"} if (webapproot)
	  xml << '>'
	  html_forms.each() do |html_form|
	      xml << html_form.to_xml
	  end
	  xml << '</HTMLForms>'
      end

   end

   # When using ssh-key, this represents the PEM-format keypair information.
   class PEMKey
      # TODO
   end
end
