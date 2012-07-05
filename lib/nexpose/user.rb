module Nexpose

  # Summary only returned by API when issuing a listing request.
  class UserSummary
    attr_reader :id, :auth_source, :auth_module, :user_name, :full_name, :email
    attr_reader :is_admin, :is_disabled, :is_locked, :site_count, :group_count

    def initialize(id, auth_source, auth_module, user_name, full_name, email, is_admin, is_disabled, is_locked, site_count, group_count)
      @id = id
      @auth_source = auth_source
      @auth_module = auth_module
      @user_name = user_name
      @full_name = full_name
      @email = email
      @is_admin = is_admin
      @is_disabled = is_disabled
      @is_locked = is_locked
      @site_count = site_count
      @group_count = group_count
    end

    def to_s
      out = "#{@user_name} (#{@full_name}) [ID: #{@id}]"
      out << " e-mail: #{@email}" unless @email.empty?
      out << " Administrator" if @is_admin
      out << " Disabled" if @is_disabled
      out << " Locked" if @is_locked
      out << ", sites: #{@site_count}"
      out << ", groups: #{@group_count}"
    end

    # Provide a list of user accounts and information about those accounts.
    def self.listing(connection)
      xml = '<UserListingRequest session-id="' + connection.session_id + '" />'
      r = connection.execute(xml, '1.1')
      if r.success
        res = []
        r.res.elements.each('UserListingResponse/UserSummary') do |summary|
          res << UserSummary.new(
            summary.attributes['id'].to_i,
            summary.attributes['authSource'],
            summary.attributes['authModule'],
            summary.attributes['userName'],
            summary.attributes['fullName'],
            summary.attributes['email'],
            summary.attributes['administrator'].to_s.chomp.eql?('1'),
            summary.attributes['disabled'].to_s.chomp.eql?('1'),
            summary.attributes['locked'].to_s.chomp.eql?('1'),
            summary.attributes['siteCount'].to_i,
            summary.attributes['groupCount'].to_i)
        end
        res
      else
        false
      end
    end

    # Retrieve the User ID based upon the user's login name.
    def self.get_user_id(connection, user_name)
      xml = '<UserListingRequest session-id="' + connection.session_id + '" />'
      r = connection.execute(xml, '1.1')
      if r.success
        r.res.elements.each('UserListingResponse/UserSummary') do |user|
          return user.attributes['id'] if user_name.eql? user.attributes['userName']
        end
      end
      return -1
    end
  end

  class UserConfig
    # user id, set to -1 to create a new user
    attr_reader :id
    # valid roles: global-admin|security-manager|site-admin|system-admin|user|custom
    attr_accessor :role_name
    # Required fields
    attr_reader :name
    attr_accessor :full_name
    # Will default to XML (1) for global-admin, Data Source (2) otherwise,
    # but caller can override (e.g., using LDAP authenticator).
    attr_accessor :authsrcid
    # Optional fields
    attr_accessor :email, :password, :sites, :groups
    # 1 to enable this user, 0 to disable
    attr_accessor :enabled
    # Boolean values
    attr_accessor :all_sites, :all_groups

    def initialize(name, full_name, password, role_name = 'user', id = -1, enabled = 1, email = nil, all_sites = false, all_groups = false)
      @name = name
      @password = password
      @role_name = role_name
      @authsrcid = ('global-admin'.eql? @role_name) ? '1' : '2'
      @id = id
      @enabled = enabled
      @full_name = full_name
      @email = email
      @all_sites = all_sites || role_name == 'global-admin'
      @all_groups = all_groups || role_name == 'global-admin'
      @sites = []
      @groups = []
    end

    def to_s
      out = "#{@user_name} (#{@full_name}) [ID: #{@id}, Role: #{@role_name}]"
      out << " Disabled" unless @enabled
      out << " All-Sites" if @all_sites
      out << " All-Groups" if @all_groups
      out << " e-mail: #{@email}" unless @email.nil? || @email.empty?
      out
    end

    def to_xml
      xml = "<UserConfig"
      xml << %Q{ id="#{@id}"}
      xml << %Q{ authsrcid="#{@authsrcid}"}
      xml << %Q{ name="#{@name}"}
      xml << %Q{ fullname="#{@full_name}"}
      xml << %Q{ role-name="#{@role_name}"}
      xml << %Q{ password="#{@password}"} if @password
      xml << %Q{ email="#{@email}"} if @email
      xml << %Q{ enabled="#{@enabled}"}
      # These two fields are keying off role_name to work around a defect.
      xml << %Q{ allGroups="#{@all_groups || @role_name == 'global-admin'}"}
      xml << %Q{ allSites="#{@all_sites || @role_name == 'global-admin'}"}
      xml << ">"
      @sites.each do |site|
        xml << %Q{<site id="#{site}" />}
      end
      @groups.each do |group|
        xml << %Q{<group id="#{group}" />}
      end
      xml << '</UserConfig>'
    end

    # Save a user configuration. Returns the (new) user ID if successful.
    def save(connection)
      xml = '<UserSaveRequest session-id="' + connection.session_id + '">'
      xml << to_xml
      xml << '</UserSaveRequest>'
      r = connection.execute(xml, '1.1')
      if r.success
        res = []
        r.res.elements.each('UserSaveResponse') do |attr|
          @id = attr.attributes['id'].to_i
        end
        @id
      else
        -1
      end
    end

    # Issue a UserConfigRequest to load an existing UserConfig from Nexpose.
    def self.load(connection, user_id)
      xml = '<UserConfigRequest session-id="' + connection.session_id + '"'
      xml << %Q{ id="#{user_id}"}
      xml << ' />'
      r = connection.execute(xml, '1.1')
      if r.success
        r.res.elements.each('UserConfigResponse/UserConfig') do |config|
          id = config.attributes['id']
          role_name = config.attributes['role-name']
          authsrcid = config.attributes['authsrcid']
          name = config.attributes['name']
          fullname = config.attributes['fullname']

          email = config.attributes['email']
          password = config.attributes['password']
          enabled = config.attributes['enabled'].to_i
          all_sites = config.attributes['allSites'] == 'true' ? true : false
          all_groups = config.attributes['allGroups'] == 'true' ? true : false
          # Not trying to load sites and groups.
          # Looks like API currently doesn't return that info to load.
          return UserConfig.new(name, fullname, password, role_name, id, enabled, email, all_sites, all_groups)
        end
      end
    end

    # Delete a user account.
    def self.delete(connection, user_id)
      xml = '<UserDeleteRequest session-id="' + connection.session_id + '"'
      xml << %Q{ id="#{user_id}"}
      xml << ' />'
      r = connection.execute(xml, '1.1')
      if r.success
        r.res.elements.each('UserConfigResponse/UserConfig') do |config|
          '1'.eql? config.attributes['id']
        end
      end
    end

    # Delete the user account associated with this object.
    def delete(connection)
      UserConfig.delete(connection, @id)
    end
  end

  class UserAuthenticator
    attr_reader :id, :auth_source, :auth_module, :external

    def initialize(id, auth_module, auth_source, external = false)
      @id = id
      @auth_source = auth_source
      @auth_module = auth_module
      @external = external
    end

    # Provide a list of user authentication sources.
    # * *Returns* : An array of known user authenticator sources.
    def self.list(connection)
      r = connection.execute('<UserAuthenticatorListingRequest session-id="' + connection.session_id + '" />', '1.1')
      if r.success
        modules = []
        r.res.elements.each('UserAuthenticatorListingResponse/AuthenticatorSummary') do |summary|
          modules << UserAuthenticator.new(summary.attributes['id'], summary.attributes['authModule'], summary.attributes['authSource'], ('1'.eql? summary.attributes['external']))
        end
        modules
      end
    end
  end
end
