module Nexpose

  class Connection
    include XMLUtils
    def list_silo_users
      r = execute(make_xml('MultiTenantUserListingRequest'), '1.2')
      arr = []
      if r.success
        r.res.elements.each('MultiTenantUserListingResponse/MultiTenantUserSummaries/MultiTenantUserSummary') do |user|
          arr << MultiTenantUserSummary.parse(user)
        end
      end
      arr
    end

    # Delete the specified silo user
    #
    # @return Whether or not the delete request succeeded.
    #
    def delete_silo(user_id)
      r = execute(make_xml('MultiTenantUserDeleteRequest', {'user-id' => user_id}), '1.2')
      r.success
    end
  end

  class MultiTenantUserSummary
    attr_accessor :id
    attr_accessor :full_name
    attr_accessor :user_name
    attr_accessor :email
    attr_accessor :superuser
    attr_accessor :enabled
    attr_accessor :auth_module
    attr_accessor :auth_source
    attr_accessor :silo_count
    attr_accessor :locked

    def self.parse(xml)
      user = new
      user.id = xml.attributes['id'].to_i
      user.full_name = xml.attributes['full-name']
      user.user_name = xml.attributes['user-name']
      user.email = xml.attributes['email']
      user.superuser = xml.attributes['superuser']
      user.enabled = xml.attributes['enabled']
      user.auth_module = xml.attributes['auth-module']
      user.auth_source = xml.attributes['auth-source']
      user.silo_count = xml.attributes['silo-count']
      user.locked = xml.attributes['locked']
      user
    end
  end

  class MultiTenantUser
    attr_accessor :id
    attr_accessor :full_name
    attr_accessor :user_name
    attr_accessor :auth_source_id
    attr_accessor :email
    attr_accessor :password
    attr_accessor :superuser
    attr_accessor :enabled
    attr_accessor :silo_access

    # Updates this silo user on a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this silo user will be saved.
    # @return [String] User ID assigned to this configuration, if successful.
    #
    def update(connection)
      r = connection.execute('<MultiTenantUserUpdateRequest session-id="' + connection.session_id + '">' + to_xml + ' </MultiTenantUserUpdateRequest>', '1.2')
      @id = r.attributes['user-id'] if r.success
    end

    # Saves this silo user to a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this silo user will be saved.
    # @return [String] User ID assigned to this configuration, if successful.
    #
    def create(connection)
      r = connection.execute('<MultiTenantUserCreateRequest session-id="' + connection.session_id + '">' + to_xml + ' </MultiTenantUserCreateRequest>', '1.2')
      @id = r.attributes['user-id'] if r.success
    end

    def as_xml
      xml = REXML::Element.new('MultiTenantUserConfig')
      xml.add_attributes({'id' => @id,
                          'full-name' => @full_name,
                          'user-name' => @user_name,
                          'authsrcid' => @auth_source_id,
                          'email' => @email,
                          'password' => @password,
                          'superuser' => @superuser,
                          'enabled' => @enabled })
      siloaccesses = xml.add_element('SiloAccesses')
      @silo_access.each { |silo_access| siloaccesses.add_element(silo_access.as_xml)}
      xml
    end

    def to_xml
      as_xml.to_s
    end

    def self.parse(xml)
      puts xml
      user = new
      user.id = xml.attributes['id'].to_i
      user.full_name = xml.attributes['full-name']
      user.user_name = xml.attributes['user-name']
      user.email = xml.attributes['email']
      user.superuser = xml.attributes['superuser']
      user.enabled = xml.attributes['enabled']
      user.auth_source_id = xml.attributes['authsrcid']
      user.silo_access = []
      xml.elements.each('SiloAccesses/SiloAccess') { |access| user.silo_access << SiloAccess.parse(access) }
      user
    end

    def self.load(connection, id)
      xml = '<MultiTenantUserConfigRequest session-id="' + connection.session_id + '"'
      xml << %( user-id="#{id}")
      xml << ' />'
      r = connection.execute(xml, '1.2')

      if r.success
        r.res.elements.each('MultiTenantUserConfigResponse/MultiTenantUserConfig') do |config|
          return MultiTenantUser.parse(config)
        end
      end
      nil
    end
  end

  class SiloAccess
    attr_accessor :all_groups
    attr_accessor :all_sites
    attr_accessor :role_name
    attr_accessor :silo_id
    attr_accessor :default
    attr_accessor :sites
    attr_accessor :groups

    def as_xml
      xml = REXML::Element.new('SiloAccess')
      xml.add_attributes({'all-groups' => @all_groups,
                         'all-sites' => @all_sites,
                         'role-name' => @role_name,
                         'silo-id' => @silo_id,
                         'default-silo' => @default})

      unless @groups.empty?
        groups = xml.add_element('AllowedGroups')
        @groups.each do |group|
          groups.add_element('AllowedGroup', {'id' => group})
        end
      end

      unless @sites.empty?
        sites = xml.add_element('AllowedSites')
        @sites.each do |site|
          sites.add_element('AllowedSite', {'id' => site})
        end
      end

      xml
    end

    def to_xml
      as_xml.to_s
    end

    def self.parse(xml)
      access = new
      access.all_groups = xml.attributes['all-groups']
      access.all_sites = xml.attributes['all-sites']
      access.role_name = xml.attributes['role-name']
      access.silo_id = xml.attributes['silo-id']
      access.default = xml.attributes['default-silo']
      access.sites = []
      xml.elements.each('AllowedSites/AllowedSite') {|site| access.sites << site.attributes['id'].to_i }
      access.groups = []
      xml.elements.each('AllowedGroups/AllowedGroup') {|group| access.groups << group.attributes['id'].to_i }
      access
    end

  end
end