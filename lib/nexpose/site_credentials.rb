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
    # scope of credential
    attr_accessor :scope

    #Create a credential object using name, id, description, host and port
    def self.for_service(name, id = -1, desc = nil, host = nil, port = nil, service = Service::CIFS)
      cred = new
      cred.name = name
      cred.id = id.to_i
      cred.enabled = true
      cred.description = desc
      cred.host_restriction = host
      cred.port_restriction = port
      cred.service = service
      cred.scope = Scope::SITE_SPECIFIC
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
        community_name: community_name,
        scope: scope
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
      c = community_name <=> other.community_name
      return c unless c == 0
      scope <=> other.scope
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
      community_name.eql?(other.community_name) &&
      scope.eql?(other.scope)
    end

  end
end
