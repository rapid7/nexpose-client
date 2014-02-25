module Nexpose

  class Connection
    include XMLUtils

    # Retrieve a list of all sites the user is authorized to view or manage.
    #
    # @return [Array[SiloSummary]] Array of SiteSummary objects.
    #
    def list_silos
      r = execute(make_xml('SiloListingRequest'), '1.2')
      arr = []
      if r.success
        r.res.elements.each('SiloListingResponse/SiloSummaries/SiloSummary') do |silo|
          arr << SiloSummary.parse(silo)
        end
      end
      arr
    end

    # Delete the specified silo
    #
    # @return Whether or not the delete request succeeded.
    #
    def delete_silo(silo_id)
      r = execute(make_xml('SiloDeleteRequest', {'silo-id' => silo_id}), '1.2')
      r.success
    end
  end

  class Silo
    attr_accessor :id
    attr_accessor :silo_profile_id
    attr_accessor :name
    attr_accessor :description
    attr_accessor :max_assets
    attr_accessor :max_users
    attr_accessor :max_hosted_assets
    attr_accessor :merchant
    attr_accessor :organization

    def self.load(connection, id)
      xml = '<SiloConfigRequest session-id="' + connection.session_id + '"'
      xml << %( silo-id="#{id}")
      xml << ' />'
      r = connection.execute(xml, '1.2')

      if r.success
        r.res.elements.each('SiloConfigResponse/SiloConfig') do |config|
          return Silo.parse(config)
        end
      end
      nil
    end

    # Updates this silo on a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this site will be saved.
    # @return [String] Silo ID assigned to this configuration, if successful.
    #
    def update(connection)
      r = connection.execute('<SiloUpdateRequest session-id="' + connection.session_id + '">' + to_xml + ' </SiloUpdateRequest>', '1.2')
      @id = r.attributes['id'] if r.success
    end

    # Saves this silo to a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this site will be saved.
    # @return [String] Silo ID assigned to this configuration, if successful.
    #
    def create(connection)
      r = connection.execute('<SiloCreateRequest session-id="' + connection.session_id + '">' + to_xml + ' </SiloCreateRequest>', '1.2')
      @id = r.attributes['id'] if r.success
    end

    def as_xml
      xml = REXML::Element.new('SiloConfig')
      xml.add_attributes({'description' => @description, 'name' => @name, 'id' => @id, 'silo-profile-id' => @silo_profile_id, 'max-assets' => @max_assets, 'max-users' => @max_users, 'max-hosted-assets' => @max_hosted_assets})
      xml.add(@merchant.as_xml) if @merchant
      xml.add(@organization.as_xml) if @organization
      xml
    end

    def to_xml
      as_xml.to_s
    end

    def self.parse(xml)
      silo = new
      silo.id = xml.attributes['id']
      silo.silo_profile_id = xml.attributes['silo-profile-id']
      silo.name = xml.attributes['name']
      silo.max_assets = xml.attributes['max-assets']
      silo.max_users = xml.attributes['max-users']
      silo.max_hosted_assets = xml.attributes['max-hosted-assets']
      silo.description = xml.attributes['description'] if xml.attributes['description']
      xml.elements.each('Merchant') do |merchant|
        silo.merchant = Merchant.parse(merchant)
      end
      xml.elements.each('Organization') do |organization|
        silo.organization = Organization.parse(organization)
      end
      silo
    end
  end

  class Address
    attr_accessor :line1
    attr_accessor :line2
    attr_accessor :city
    attr_accessor :state
    attr_accessor :zip
    attr_accessor :country

    def self.parse(xml)
      address = new
      address.line1 = xml.attributes['line1']
      address.line2 = xml.attributes['line2']
      address.city = xml.attributes['city']
      address.state = xml.attributes['state']
      address.zip = xml.attributes['zip']
      address.country = xml.attributes['country']
      address
    end

    def as_xml
      xml = REXML::Element.new('Address')
      xml.add_attributes({'city' => @city, 'country' => @country, 'line1' => @line1, 'line2' => @line2, 'state' => @state, 'zip' => @zip})
      xml
    end
  end

  class Organization
    attr_accessor :company
    attr_accessor :first_name
    attr_accessor :last_name
    attr_accessor :phone
    attr_accessor :address
    attr_accessor :email
    attr_accessor :title
    attr_accessor :url

    def as_xml
      xml = REXML::Element.new('Organization')
      xml.add_attributes({'company' => @company, 'email-address' => @email, 'first-name' => @first_name, 'last-name' => @last_name, 'phone-number' => @phone, 'title' => @title, 'url' => @url})
      xml.add(@address.as_xml)
      xml
    end

    def self.parse(xml)
      organization = new
      organization.company = xml.attributes['company']
      organization.first_name = xml.attributes['first-name']
      organization.last_name = xml.attributes['last-name']
      organization.phone = xml.attributes['phone-number']
      xml.elements.each('Address') { |address| merchant.address = Address.parse(address) }
      organization.email = xml.attributes['email']
      organization.title = xml.attributes['title']
      organization.url = xml.attributes['url']
    end
  end

  class Merchant < Organization
    attr_accessor :acquirer_relationship
    attr_accessor :agent_relationship
    attr_accessor :ecommerce
    attr_accessor :grocery
    attr_accessor :mail_order
    attr_accessor :payment_application
    attr_accessor :payment_version
    attr_accessor :petroleum
    attr_accessor :retail
    attr_accessor :telecommunication
    attr_accessor :travel
    attr_accessor :dbas
    attr_accessor :industries
    attr_accessor :qsa

    def self.parse(xml)
      merchant = new
      merchant.acquirer_relationship = xml.attributes['acquirer-relationship']
      merchant.agent_relationship = xml.attributes['agent-relationship']
      merchant.ecommerce = xml.attributes['ecommerce']
      merchant.grocery = xml.attributes['grocery']
      merchant.mail_order = xml.attributes['mail-order']
      merchant.payment_application = xml.attributes['payment-application']
      merchant.payment_version = xml.attributes['payment-version']
      merchant.petroleum = xml.attributes['petroleum']
      merchant.retail = xml.attributes['retail']
      merchant.telecommunication = xml.attributes['telecommunication']
      merchant.travel = xml.attributes['travel']
      merchant.company = xml.attributes['company']
      merchant.first_name = xml.attributes['first-name']
      merchant.last_name = xml.attributes['last-name']
      merchant.phone = xml.attributes['phone-number']
      xml.elements.each('Address') { |address| merchant.address = Address.parse(address) }
      merchant.dbas = []
      xml.elements.each('DBAs/DBA') { |dba| merchant.dbas << dba.attributes['name'] }
      merchant.industries = []
      xml.elements.each('OtherIndustries/Industry') { |industry| merchant.industries << industry.attributes['name'] }
      merchant.qsa = []
      xml.elements.each('QSA') { |organization| merchant.qsa << Organization.parse(organization) }
      merchant.email = xml.attributes['email']
      merchant.title = xml.attributes['title']
      merchant.url = xml.attributes['url']
      merchant
    end

    def as_xml
      xml = super
      xml.name = 'Merchant'
      xml.add_attributes({'acquirer-relationship' => @acquirer_relationship, 'agent-relationship' => @agent_relationship, 'ecommerce' => @ecommerce, 'grocery' => @grocery, 'mail-order' => @mail_order})
      xml.add_attributes({'payment-application' => @payment_application, 'payment-version' => @payment_version, 'petroleum' => @petroleum, 'retail' => @retail, 'telecommunication' => @telecommunication, 'travel' => @travel})
      unless dbas.empty?
        dbas = REXML::Element.new('DBAs')
        @dbas.each do |dba|
          dbas.add_element('DBA', {'name' => dba})
        end
      end
      unless @industries.empty?
        industires = REXML::Element.new('OtherIndustries')
        @industries.each do |industry|
          dbas.add_element('Industry', {'name' => industry})
        end
      end
      xml.add(@qsa.as_xml) unless @qsa.empty?
      xml
    end
  end

  # Object that represents the summary of a Nexpose Site.
  #
  class SiloSummary
    # The silo ID.
    attr_accessor :id
    # The silo name.
    attr_accessor :name
    # A description of the silo.
    attr_accessor :description
    # The ID of the silo profile being used for this silo.
    attr_accessor :silo_profile_id
    # The asset count for this silo
    attr_accessor :assets
    # The asset count limit for this silo.
    attr_accessor :max_assets
    # The hosted asset count limit for this silo.
    attr_accessor :max_hosted_assets
    # The user count for this silo
    attr_accessor :users
    # The user count limit for this silo.
    attr_accessor :max_users


    def self.parse(xml)
      puts xml
      summary = new
      summary.id = xml.attributes['id']
      summary.name = xml.attributes['name']
      summary.description = xml.attributes['description']
      summary.silo_profile_id = xml.attributes['silo-profile-id']
      xml.elements.each('LicenseSummary') do |license|
        summary.assets = license.attributes['assets']
        summary.max_assets = license.attributes['max-assets']
        summary.max_hosted_assets = license.attributes['max-hosted-assets']
        summary.users = license.attributes['users']
        summary.max_users = license.attributes['max-users']
      end
      summary
    end
  end
end
