module Nexpose

  # Object that represents administrative credentials to be used
  # during a scan. When retrieved from an existing site configuration
  # the credentials will be returned as a security blob and can only
  # be passed back as is during a Site Save operation. This object
  # can only be used to create a new set of credentials.
  #
  class SiteCredentials < Credential

    # Unique identifier of the credential on the Nexpose console.
    attr_accessor :id
    # The service for these credentials.
    attr_accessor :service
    # The host for these credentials.
    attr_accessor :host_restriction
    # The port on which to use these credentials.
    attr_accessor :port_restriction
    # The password
    attr_accessor :password
    # The name
    attr_accessor :name
    # is this credential enable on site or not.
    attr_accessor :enabled
    # the description of credential
    attr_accessor :description
    # domain of the service
    attr_accessor :domain
    # database of the service
    attr_accessor :database
    # The type of privilege escalation to use (sudo/su)
    # Permission elevation type. See Nexpose::Credential::ElevationType.
    attr_accessor :permission_elevation_type
    # The userid to use when escalating privileges (optional)
    attr_accessor :permission_elevation_user
    # The password to use when escalating privileges (optional)
    attr_accessor :permission_elevation_password
    # The authentication type to use with SNMP v3 credentials
    attr_accessor :authentication_type
    # The privacy/encryption type to use with SNMP v3 credentials
    attr_accessor :privacy_type
    # The privacy/encryption pass phrase to use with SNMP v3 credentials
    attr_accessor :privacy_password
    # the user name to be used in service
    attr_accessor :user_name
    # the notes password
    attr_accessor :notes_id_password
    # use windows auth
    attr_accessor :use_windows_auth
    # sid for oracle
    attr_accessor :sid
    #for ssh public key require pem format private key
    attr_accessor :pem_format_private_key
    # for snmp v1/v2
    attr_accessor :community_name

    #Create a credential object using name, id, description, host and port
    def self.for_service(name, id = -1, desc = nil, host = nil, port = nil, service = Service.CIFS)
      cred = new
      cred.name = name
      cred.id = id.to_i
      cred.enabled = true
      cred.description = desc
      cred.host_restriction = host
      cred.port_restriction = port
      cred.service = service
      cred
    end

    # Load an credential from the provided console.
    #
    # @param [Connection] nsc Active connection to a Nexpose console.
    # @param [String] id Unique identifier of an site.
    # @param [String] id Unique identifier of an credential.
    # @return [SiteCredential] The requested credential of site, if found.
    #
    def self.load(nsc, site_id, credential_id)
      uri = "/api/2.1/sites/#{site_id}/credentials/#{credential_id}"
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      hash = JSON.parse(resp, symbolize_names: true)
      new.object_from_hash(nsc, hash)
    end

    # Copy an existing configuration from a Nexpose instance.
    # Returned object will reset the credential ID and append "Copy" to the existing
    # name.
    #
    # @param [Connection] connection Connection to the security console.
    # @param [String] id Unique identifier of an site.
    # @param [String] id Unique identifier of an credential.
    # @return [SiteCredentials] Site credential loaded from a Nexpose console.
    #
    def self.copy(connection, site_id, credential_id)
      siteCredential = self.load(connection, site_id, credential_id)
      siteCredential.id = -1
      siteCredential.name = "#{siteCredential.name} Copy"
      siteCredential
    end

    # Copy an existing configuration from a site credential.
    # Returned object will reset the credential ID and append "Copy" to the existing
    # name.
    #
    # @param [siteCredential] site credential to be copied.
    # @return [SiteCredentials] modified.
    #
    def self.copy(siteCredential)
      siteCredential.id = -1
      siteCredential.name = "#{siteCredential.name} Copy"
      siteCredential
    end

    def to_json
      JSON.generate(to_h)
    end

    def to_h
      { id: id,
        service: service,
        host_restriction: host_restriction,
        port_restriction: port_restriction,
        password: password,
        name: name,
        enabled: enabled,
        description: description,
        domain: domain,
        database: database,
        permission_elevation_type: permission_elevation_type,
        permission_elevation_user: permission_elevation_user,
        permission_elevation_password: permission_elevation_password,
        authentication_type: authentication_type,
        privacy_type: privacy_type,
        privacy_password: privacy_password,
        user_name: user_name,
        notes_id_password: notes_id_password,
        use_windows_auth: use_windows_auth,
        sid: sid,
        pem_format_private_key: pem_format_private_key,
        community_name: community_name
      }
    end

    def <=>(other)
      c = id <=> other.id
      return c unless c == 0
      c = service <=> other.service
      return c unless c == 0
      c = host_restriction <=> other.host_restriction
      return c unless c == 0
      c = port_restriction <=> other.port_restriction
      return c unless c == 0
      c = password <=> other.password
      return c unless c == 0
      c = name <=> other.name
      return c unless c == 0
      c = enabled <=> other.enabled
      return c unless c == 0
      c = description <=> other.description
      return c unless c == 0
      c = domain <=> other.domain
      return c unless c == 0
      c = database <=> other.database
      return c unless c == 0
      c = permission_elevation_type <=> other.permission_elevation_type
      return c unless c == 0
      c = permission_elevation_user <=> other.permission_elevation_user
      return c unless c == 0
      c = permission_elevation_password <=> other.permission_elevation_password
      return c unless c == 0
      c = authentication_type <=> other.authentication_type
      return c unless c == 0
      c = privacy_type <=> other.privacy_type
      return c unless c == 0
      c = privacy_password <=> other.privacy_password
      return c unless c == 0
      c = user_name <=> other.user_name
      return c unless c == 0
      c = notes_id_password <=> other.notes_id_password
      return c unless c == 0
      c = use_windows_auth <=> other.use_windows_auth
      return c unless c == 0
      c = sid <=> other.sid
      return c unless c == 0
      c = pem_format_private_key <=> other.pem_format_private_key
      return c unless c == 0
      community_name <=> other.community_name
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      id.eql?(other.id) &&
      service.eql?(other.service) &&
      host_restriction.eql?(other.host_restriction) &&
      port_restriction.eql?(other.port_restriction) &&
      password.eql?(other.password) &&
      name.eql?(other.name) &&
      enabled.eql?(other.enabled) &&
      description.eql?(other.description) &&
      domain.eql?(other.domain) &&
      database.eql?(other.database) &&
      permission_elevation_type.eql?(other.permission_elevation_type) &&
      permission_elevation_user.eql?(other.permission_elevation_user) &&
      permission_elevation_password.eql?(other.permission_elevation_password) &&
      authentication_type.eql?(other.authentication_type) &&
      privacy_type.eql?(other.privacy_type) &&
      privacy_password.eql?(other.privacy_password) &&
      user_name.eql?(other.user_name) &&
      notes_id_password.eql?(other.notes_id_password) &&
      use_windows_auth.eql?(other.use_windows_auth) &&
      sid.eql?(other.sid) &&
      pem_format_private_key.eql?(other.pem_format_private_key) &&
      community_name.eql?(other.community_name)
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

    def as_xml
      attributes = {}
      attributes['name'] = @name
      attributes['value'] = @value

      make_xml('Header', attributes)
    end
    alias_method :to_xml_elem, :as_xml
  end

  # Object that represents Headers, associated with Web Session Authentication.
  #
  class Headers
    include XMLUtils

    # A regular expression used to match against the response to identify authentication failures.
    attr_reader :soft403
    # Base URL of the application for which the form authentication applies.
    attr_reader :webapproot
    # When using HTTP headers, this represents the set of headers to pass with the authentication request.
    attr_reader :headers

    def initialize(webapproot, soft403)
      @headers = []
      @webapproot = webapproot
      @soft403 = soft403
    end

    def add_header(header)
      @headers.push(header)
    end

    def as_xml
      attributes = {}
      attributes['webapproot'] = @webapproot
      attributes['soft403'] = @soft403

      xml = make_xml('Headers', attributes)
      @headers.each do |header|
        xml.add_element(header.to_xml_elem)
      end
      xml
    end
    alias_method :to_xml_elem, :as_xml

  end

  # When using HTML form, this represents the login form information.
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

    def as_xml
      attributes = {}
      attributes['name'] = @name
      attributes['value'] = @value
      attributes['type'] = @type
      attributes['dynamic'] = @dynamic
      attributes['checked'] = @checked

      make_xml('Field', attributes)
    end
    alias_method :to_xml_elem, :as_xml
  end

  # When using HTML form, this represents the login form information.
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

    def as_xml
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
    alias_method :to_xml_elem, :as_xml
  end

  # When using HTML form, this represents the login form information.
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

    def as_xml
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
    alias_method :to_xml_elem, :as_xml
  end

  # When using ssh-key, this represents the PEM-format key-pair information.
  class PEMKey
    # TODO
  end
end
