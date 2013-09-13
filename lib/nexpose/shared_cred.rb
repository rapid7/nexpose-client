module Nexpose

  module NexposeAPI

    def list_shared_credentials
      creds = DataTable._get_json_table(self,
                                   '/data/credential/shared/listing',
                                   { 'sort' => -1,
                                     'table-id' => 'credential-listing' })
      creds.map { |c| SharedCredentialSummary.from_json(c) }
    end

    alias_method :list_shared_creds, :list_shared_credentials
    alias_method :shared_credentials, :list_shared_credentials
    alias_method :shared_creds, :list_shared_credentials
  end

  class SharedCredentialSummary

    # Unique ID assigned to this credential by Nexpose.
    attr_accessor :id
    # Name to identify this credential.
    attr_accessor :name
    # The credential type. See Nexpose::Credential::Type.
    attr_accessor :type
    # Domain or realm.
    attr_accessor :domain
    # User name.
    attr_accessor :username
    # User name to use when elevating permissions (e.g., sudo).
    attr_accessor :privilege_username
    # Boolean to indicate whether this credential applies to all sites.
    attr_accessor :all_sites
    # When this credential was last modified.
    attr_accessor :last_modified

    def self.from_json(json)
      cred = new
      cred.id = json['credentialID']['ID']
      cred.name = json['name']
      cred.type = json['service']
      cred.domain = json['domain']
      cred.username = json['username']
      cred.privilege_username = json['privilegeElevationUsername']
      cred.all_sites = json['scope'] == 'ALL_SITES_ENABLED_DEFAULT'
      cred.last_modified = Time.at(json['lastModified']['time'] / 1000)
      cred
    end
  end

  class SharedCredential < SharedCredentialSummary

    # Optional description of this credential.
    attr_accessor :description

    # Database or SID.
    attr_accessor :database
    # Windows/Samba LM/NTLM Hash.
    attr_accessor :ntlm_hash
    # Password or SNMP community name.
    attr_accessor :password
    # PEM-format private key.
    attr_accessor :pem_key
    # Password to use when elevating permissions (e.g., sudo).
    attr_accessor :privilege_password
    # Permission elevation type. See Nexpose::Credential::ElevationType.
    attr_accessor :privilege_type

    # IP address or host name to restrict this credential to.
    attr_accessor :host
    # Single port to restrict this credential to.
    attr_accessor :port

    # Array of site IDs that this credential is restricted to.
    attr_accessor :sites

    # Whether this credential is enabled or should be enabled when saved.
    attr_accessor :enabled

    def initialize(name, id = -1)
      @name, @id = name, id.to_i
      @sites = []
      @enabled = true
    end

    def self.load(nsc, id)
      response = AJAX.get(nsc, "/data/credential/shared/get?credid=#{id}")
      parse(response)
    end

    # Save this credential to the security console.
    #
    # @param [Connection] nsc An active connection to a Nexpose console.
    # @return [Boolean] Whether the save succeeded.
    #
    def save(nsc)
      response = AJAX.post(nsc, '/data/credential/shared/save', to_xml)
      !!(response =~ /success="1"/)
    end

    def to_xml
      xml = '<Credential '
      xml << %( id="#{@id}")
      xml << ' shared="1"'
      xml << %( enabled="#{@enabled ? 1 : 0}">)

      xml << %(<Name>#{@name}</Name>)
      xml << %(<Description>#{@description}</Description>)

      xml << %(<Services><Service type="#{@type}"></Service></Services>)

      xml << '<Account type="nexpose">'
      xml << %(<Field name="database">#{@database}</Field>)
      xml << %(<Field name="domain">#{@domain}</Field>)
      xml << %(<Field name="username">#{@username}</Field>)
      xml << %(<Field name="ntlmhash">#{@ntlm_hash}</Field>) if @ntlm_hash
      xml << %(<Field name="password">#{@password}</Field>) if @password
      xml << %(<Field name="pemkey">#{@pem_key}</Field>) if @pem_key
      xml << %(<Field name="privilegeelevationusername">#{@privilege_username}</Field>)
      xml << %(<Field name="privilegeelevationpassword">#{@privilege_password}</Field>) if @privilege_password
      xml << %(<Field name="privilegeelevationtype">#{@privilege_type}</Field>) if @privilege_type
      xml << '</Account>'

      xml << '<Restrictions>'
      xml << %(<Restriction type="host">#{@host}</Restriction>) if @host
      xml << %(<Restriction type="port">#{@port}</Restriction>) if @port
      xml << '</Restrictions>'

      xml << %(<Sites all="#{@all_sites ? 1 : 0}">)
      @sites.each do |site|
        xml << %(<Site id="#{site}"></Site>)
      end
      xml << '</Sites>'

      xml << '</Credential>'
    end

    def self.parse(xml)
      rexml = REXML::Document.new(xml)
      rexml.elements.each('Credential') do |c|
        cred = new(c.elements['Name'].text, c.attributes['id'].to_i)

        desc = c.elements['Description']
        cred.description = desc.text if desc

        c.elements.each('Account/Field') do |field|
          case field.attributes['name']
          when 'database'
            cred.database = field.text
          when 'domain'
            cred.domain = field.text
          when 'username'
            cred.username = field.text
          when 'password'
            cred.password = field.text
          when 'ntlmhash'
            cred.ntlm_hash = field.text
          when 'pemkey'
            cred.pem_key = field.text
          when 'privilegeelevationusername'
            cred.privilege_username = field.text
          when 'privilegeelevationpassword'
            cred.privilege_password = field.text
          when 'privilegeelevationtype'
            cred.privilege_type = field.text
          end
        end

        service = REXML::XPath.first(c, 'Services/Service')
        cred.type = service.attributes['type']

        c.elements.each('Restrictions/Restriction') do |r|
          cred.host = r.text if r.attributes['type'] == 'host'
          cred.port = r.text.to_i if r.attributes['type'] == 'port'
        end

        sites = REXML::XPath.first(c, 'Sites')
        cred.all_sites = sites.attributes['all'] == '1'

        unless cred.all_sites
          sites.elements.each('Site') do |site|
            cred.sites << site.attributes['id'].to_i
          end
        end

        return cred
      end
      nil
    end
  end
end
