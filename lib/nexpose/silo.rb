module Nexpose

  class Connection
    include XMLUtils

 # Retrieve a list of all sites the user is authorized to view or manage.
    #
    # @return [Array[SiteSummary]] Array of SiteSummary objects.
    #
    def list_silos
      r = execute(make_xml('SiloListingRequest'), '1.2')
      arr = []
      if r.success
        r.res.elements.each('SiloListingResponse/SiloSummaries/SiloSummary') do |site|
          arr << SiloSummary.new(site.attributes['id'],
                                 site.attributes['name'],
                                 site.attributes['description'],
                                 site.attributes['silo-profile-id'])
        end
      end
      arr
    end

    # Delete the specified site and all associated scan data.
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

    def initialize(id, silo_profile_id, name, max_assets, max_users, max_hosted_assets, description = nil, merchant = nil, organization = nil)
      @id = id
      @silo_profile_id = silo_profile_id
      @name = name
      @max_assets = max_assets
      @max_users = max_users
      @max_hosted_assets = max_hosted_assets
      @description = description
      @merchant = merchant
      @organization = organization
    end

    def self.load(connection, id)
      xml = '<SiloConfigRequest session-id="' + connection.session_id + '"'
      xml << %( silo-id="#{id}")
      xml << ' />'
      r = connection.execute(xml, '1.2')

      if r.success
        r.res.elements.each('SiloConfigResponse/SiloConfig') do |config|
          silo = Silo.new(config.attributes['id'],
                            config.attributes['silo-profile-id'],
                            config.attributes['name'],
                            config.attributes['max-assets'],
                            config.attributes['max-users'],
                            config.attributes['max-hosted-assets'])
          silo.description = config.attributes['description'] if config.attributes['description']
          config.elements.each('Merchant') do |merchant|
          end
          return silo 
        end
      end
      nil
    end

    # Saves this site to a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this site will be saved.
    # @return [Fixnum] Site ID assigned to this configuration, if successful.
    #
    def update(connection)
      r = connection.execute('<SiloUpdateRequest session-id="' + connection.session_id + '">' + to_xml + ' </SiloUpdateRequest>', '1.2')
      @id = r.attributes['id'] if r.success
    end
  
    def create(connection)
      r = connection.execute('<SiloCreateRequest session-id="' + connection.session_id + '">' + to_xml + ' </SiloCreateRequest>', '1.2')
      @id = r.attributes['id'] if r.success
    end

    def to_xml_elem
      xml = REXML::Element.new('SiloConfig')
      xml.add_attributes({'description' => @description, 'name' => @name, 'id' => @id, 'silo-profile-id' => @silo_profile_id, 'max-assets' => @max_assets, 'max-users' => @max_users, 'max-hosted-assets' => @max_hosted_assets})
      xml.add(@merchant.to_xml_elem) if @merchant
      xml.add(@organization.to_xml_elem) if @organization
      xml
    end

    def to_xml
      to_xml_elem.to_s
    end
  end

  class Address
    attr_accessor :zip
    attr_accessor :city
    attr_accessor :state
    attr_accessor :country
    attr_accessor :line1
    attr_accessor :line2

    def initialize(zip, city, state, country, line1, line2 = nil)
      @zip = zip
      @city = city
      @state = state
      @country = country
      @line1 = line1
      @line2 = line2
    end

    def to_xml_elem
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

    def initialize(company, first_name, last_name, phone, address, email = nil, title = nil, url = nil)
      @company = company
      @first_name = first_name
      @last_name = last_name
      @phone = phone
      @address = address
      @email = email
      @title = title
      @url = url
    end

    def to_xml_elem
      xml = REXML::Element.new('Organization')
      xml.add_attributes({'company' => @company, 'email-address' => @email, 'first-name' => @first_name, 'last-name' => @last_name, 'phone-number' => @phone, 'title' => @title, 'url' => @url})
      xml.add(@address.to_xml_elem) if @address
      xml
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

    def initialize(acquirer_relationship, agent_relationship, ecommerce, grocery, mail_order, payment_application, payment_version, petroleum, retail, telecommunication, travel, company, first_name, last_name, phone, address, email = nil, title = nil, url = nil, dbas = [], industries = [], qsa = nil)
      super(company, first_name, last_name, phone, address, email, title, url)
      @acquirer_relationship = acquirer_relationship
      @agent_relationship = agent_relationship
      @ecommerce = ecommerce
      @grocery = grocery
      @mail_order = mail_order
      @payment_application = payment_application
      @payment_version = payment_version
      @petroleum = petroleum
      @retail = retail
      @telecommunication = telecommunication
      @travel = travel
    end

    def to_xml_elem
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
      xml.add(@qsa.to_xml_elem) if @qsa
      xml
    end
  end

  # Object that represents the summary of a Nexpose Site.
  #
  class SiloSummary

    # The Silo ID.
    attr_reader :id
    # The Silo Name.
    attr_reader :name
    # A Description of the Silo.
    attr_reader :description
    # The ID of the silo profile being used for this Silo.
    attr_reader :silo_profile_id

    # Constructor
    # SiteSummary(id, name, description, riskfactor = 1)
    def initialize(id, name, silo_profile_id, description = nil )
      @id = id
      @name = name
      @description = description
      @silo_profile_id = silo_profile_id 
    end
  end
end
