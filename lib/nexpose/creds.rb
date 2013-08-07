module Nexpose

  # Object that represents administrative credentials to be used
  # during a scan. When retrieved from an existing site configuration
  # the credentials will be returned as a security blob and can only
  # be passed back as is during a Site Save operation. This object
  # can only be used to create a new set of credentials.
  #
  class AdminCredentials
    include XMLUtils

    # Security blob for an existing set of credentials
    attr_accessor :securityblob
    # Designates if this object contains user defined credentials or a security blob
    attr_accessor :isblob
    # The service for these credentials. Can be All.
    attr_accessor :service
    # The host for these credentials. Can be Any.
    attr_accessor :host
    # The port on which to use these credentials.
    attr_accessor :port
    # The user id or username
    attr_accessor :userid
    # The password
    attr_accessor :password
    # The realm for these credentials
    attr_accessor :realm
    # When using httpheaders, this represents the set of headers to pass
    # with the authentication request.
    attr_accessor :headers
    # When using htmlforms, this represents the tho form to pass the
    # authentication request to.
    attr_accessor :html_forms
    # The type of privilege escalation to use (sudo/su)
    attr_accessor :priv_type
    # The userid to use when escalating privileges (optional)
    attr_accessor :priv_username
    # The password to use when escalating privileges (optional)
    attr_accessor :priv_password

    def initialize(isblob = false)
      @isblob = isblob
    end

    # Sets the credentials information for this object.
    def set_credentials(service, host, port, userid, password, realm)
      @isblob = false
      @securityblob = nil
      @service = service
      @host = host
      @port = port
      @userid = userid
      @password = password
      @realm = realm
    end

    def self.for_service(service, user, password, realm = nil, host = nil, port = nil)
      cred = new
      cred.service = service
      cred.userid = user
      cred.password = password
      cred.realm = realm
      cred.host = host
      cred.port = port
      cred
    end

    # Sets privilege escalation credentials.  Type should be either
    # sudo/su.
    def set_privilege_credentials(type, username, password)
      @priv_type = type
      @priv_username = username
      @priv_password = password
    end

    # The name of the service.  Possible values are outlined in the
    # Nexpose API docs.
    def set_service(service)
      @service = service
    end

    def set_host(host)
      @host = host
    end

    # Credentials fetched from the API are encrypted into a
    # securityblob.  If you want to use those credentials on a
    # different site, copy the blob into the credential.
    def set_blob(securityblob)
      @isblob = true
      @securityblob = securityblob
    end

    # Add Headers to credentials for httpheaders.
    def set_headers(headers)
      @headers = headers
    end

    def set_html_forms(html_forms)
      @html_forms = html_forms
    end

    def to_xml
      to_xml_elem.to_s
    end

    def to_xml_elem
      attributes = {}

      attributes['service'] = @service
      attributes['userid'] = @userid
      attributes['password'] = @password
      attributes['realm'] = @realm
      attributes['host'] = @host
      attributes['port'] = @port

      attributes['privilegeelevationtype'] = @priv_type if @priv_type
      attributes['privilegeelevationusername'] = @priv_username if @priv_username
      attributes['privilegeelevationpassword'] = @priv_password if @priv_password

      data = isblob ? securityblob : ''
      xml = make_xml('adminCredentials', attributes, data)
      xml.add_element(@headers.to_xml_elem) if @headers
      xml.add_element(@html_forms.to_xml_elem) if @html_forms
      xml
    end

    include Comparable

    def <=>(other)
      to_xml <=> other.to_xml
    end

    def eql?(other)
      to_xml == other.to_xml
    end

    def hash
      to_xml.hash
    end
  end

  # Object that represents Header name-value pairs, associated with Web Session Authentication.
  #
  class Header
    include XMLUtils

    # Name, one per Header
    attr_reader :name
    # Value, one per Header
    attr_reader :value

    # Construct with name value pair
    def initialize(name, value)
      @name = name
      @value = value
    end

    def to_xml_elem
      attributes = {}
      attributes['name'] = @name
      attributes['value'] = @value

      make_xml('Header', attributes)
    end
  end

  # Object that represents Headers, associated with Web Session Authentication.
  #
  class Headers
    include XMLUtils

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

    def add_header(header)
      @headers.push(header)
    end

    def to_xml_elem
      attributes = {}
      attributes['webapproot'] = @webapproot
      attributes['soft403'] = @soft403

      xml = make_xml('Headers', attributes)
      @headers.each do |header|
        xml.add_element(header.to_xml_elem)
      end
      xml
    end

  end

  # When using htmlform, this represents the login form information.
  #
  class Field
    include XMLUtils

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

    def to_xml_elem
      attributes = {}
      attributes['name'] = @name
      attributes['value'] = @value
      attributes['type'] = @type
      attributes['dynamic'] = @dynamic
      attributes['checked'] = @checked

      make_xml('Field', attributes)
    end
  end

  # When using htmlform, this represents the login form information.
  #
  class HTMLForm
    include XMLUtils

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

    def to_xml_elem
      attributes = {}
      attributes['name'] = @name
      attributes['action'] = @action
      attributes['method'] = @method
      attributes['enctype'] = @enctype

      xml = make_xml('HTMLForm', attributes)

      fields.each() do |field|
        xml.add_element(field.to_xml_elem)
      end
      xml
    end
  end

  # When using htmlform, this represents the login form information.
  #
  class HTMLForms
    include XMLUtils

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

    def to_xml_elem
      attributes = {}
      attributes['parentpage'] = @parentpage
      attributes['soft403'] = @soft403
      attributes['webapproot'] = @webapproot

      xml = make_xml('HTMLForms', attributes)

      html_forms.each() do |html_form|
        xml.add_element(html_form.to_xml_elem)
      end
      xml
    end
  end

  # When using ssh-key, this represents the PEM-format keypair information.
  class PEMKey
    # TODO
  end
end
