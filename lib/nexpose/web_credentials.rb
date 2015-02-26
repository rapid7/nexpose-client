module Nexpose

  # Object that represents web credential defined in site configuration.
  module WebCredentials

    module WebAppAuthType
      HTML_FORM = 'htmlform'  # Represent HTML form credentials.
      HTTP_HEADER = 'httpheaders' # Represent HTTP header credentials.
    end

    # Object that represents Header name-value pairs, associated with Web Session Authentication.
    #
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

      def to_h
        header = Hash.new
        header[@name] = @value
        header
      end
    end

    # Object that represents Headers, associated with Web Session Authentication.
    #
    class Headers < APIObject

      # A regular expression used to match against the response to identify authentication failures.
      attr_reader :soft403Pattern
      # Base URL of the application for which the form authentication applies.
      attr_reader :baseURL
      # When using HTTP headers, this represents the set of headers to pass with the authentication request.
      attr_reader :headers
      # name of the html header
      attr_reader :name
      # is this enable for the site configuration
      attr_accessor :enabled
      #service type of header
      attr_reader :service
      # id of the header
      attr_reader :id


      def initialize(name, baseURL, soft403Pattern, id = -1, enabled = true)
        @headers = {}
        @name = name
        @baseURL = baseURL
        @soft403Pattern = soft403Pattern
        @service = WebAppAuthType::HTTP_HEADER
        @enabled = enabled
        @id = id
      end

      def add_header(header)
        @headers = @headers.merge(header.to_h)
      end

      def to_json
        JSON.generate(to_h)
      end

      def to_h
        { id: id,
          service: service,
          enabled: enabled,
          name: name,
          headers: headers,
          baseURL: baseURL,
          soft403Pattern: soft403Pattern
        }
      end

      def <=>(other)
        c = id <=> other.id
        return c unless c == 0
        c = service <=> other.service
        return c unless c == 0
        c = enabled <=> other.enabled
        return c unless c == 0
        c = name <=> other.name
        return c unless c == 0
        c = headers <=> other.headers
        return c unless c == 0
        c = baseURL <=> other.baseURL
        return c unless c == 0
        soft403Pattern <=> other.soft403Pattern
      end

      def ==(other)
        eql?(other)
      end

      def eql?(other)
        id.eql?(other.id) &&
        service.eql?(other.service) &&
        enabled.eql?(other.enabled) &&
        name.eql?(other.name) &&
        headers.eql?(other.headers) &&
        baseURL.eql?(other.baseURL) &&
        soft403Pattern.eql?(other.soft403Pattern)
      end
   end

    # When using HTML form, this represents the login form information.
    #
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

    end

    # When using HTML form, this represents the login form information.
    #
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
        @fields = []
      end

      def add_field(field)
        @fields << field
      end
    end

    # When using HTML form, this represents the login form information.
    #
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
        @html_forms = []
      end

      def add_html_form(html_form)
        @html_forms << html_form
      end

    end
  end
end

