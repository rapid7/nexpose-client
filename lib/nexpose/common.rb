module Nexpose
  # Constants useful across the Nexpose module.
  module Scope
    GLOBAL = 'global'
    SILO = 'silo'
  end

  # Configuration structure for e-mail notification.
  #
  # The send_as and send_to_acl_as attributes are optional, but one of them is
  # required for sending reports via e-mail. The send_as attribute is required
  # for sending e-mails to users who are not on the report access list.
  # The send_to_acl attribute is required for sending e-mails to report access
  # list members.
  #
  # E-mails and attachments are sent via the Internet in clear text and are not
  # encrypted. If you do not set a valid value for either attribute,
  # the application will save the report but not send it via e-mail.
  # If you set a valid value for the send_as attribute but not for the
  # send_to_acl_as attribute, the application will send the report via e-mail to
  # non-access-list members only. If you set a valid value for the
  # send_to_acl_as attribute, the application will send the report via e-mail to
  # access-list members only. If you set a valid value for both attributes,
  # the application will send reports via e-mail to access-list members and
  # non-members.
  class Email
    # Send as file attachment or zipped file to individuals who are not members
    # of the report access list. One of: file|zip
    attr_accessor :send_as
    # Send to all the authorized users of sites, groups, and assets.
    attr_accessor :to_all_authorized
    # Send to users on the report access list.
    attr_accessor :send_to_acl_as
    # Format to send to users on the report access list. One of: file|zip|url
    attr_accessor :send_to_owner_as

    # Sender that e-mail will be attributed to.
    attr_accessor :sender
    # SMTP relay server.
    attr_accessor :smtp_relay_server
    # Array of report recipients (i.e., not already on the report access list).
    attr_accessor :recipients

    def initialize(to_all_authorized, send_to_owner_as, send_to_acl_as, send_as)
      @to_all_authorized = to_all_authorized
      @send_to_owner_as = send_to_owner_as
      @send_to_acl_as = send_to_acl_as
      @send_as = send_as

      @recipients = []
    end

    def to_xml
      xml = '<Email'
      xml << %( toAllAuthorized='#{@toAllAuthorized ? 1 : 0}')
      xml << %( sendToOwnerAs='#{@send_to_owner_as}') if @send_to_owner_as
      xml << %( sendToAclAs='#{@send_to_acl_as}') if @send_to_acl_as
      xml << %( sendAs='#{@send_as}') if @send_as
      xml << '>'
      xml << %(<Sender>#{@sender}</Sender>) if @sender
      xml << %(<SmtpRelayServer>#{@smtp_relay_server}</SmtpRelayServer>) if @smtp_relay_server
      if @recipients
        xml << '<Recipients>'
        @recipients.each do |recipient|
          xml << %(<Recipient>#{recipient}</Recipient>)
        end
        xml << '</Recipients>'
      end
      xml << '</Email>'
    end

    def self.parse(xml)
      xml.elements.each('//Email') do |email|
        config = Email.new(email.attributes['toAllAuthorized'] == '1',
                           email.attributes['sendToOwnerAs'],
                           email.attributes['sendToAclAs'],
                           email.attributes['sendAs'])

        xml.elements.each('//Sender') do |sender|
          config.sender = sender.text
        end
        xml.elements.each('//SmtpRelayServer') do |server|
          config.smtp_relay_server = server.text
        end
        xml.elements.each('//Recipient') do |recipient|
          config.recipients << recipient.text
        end
        return config
      end
      nil
    end
  end

  # Configuration structure for schedules.
  class Schedule
    # Whether or not this schedule is enabled.
    attr_accessor :enabled
    # Valid schedule types: daily, hourly, monthly-date, monthly-day, weekly.
    attr_accessor :type
    # The repeat interval based upon type.
    attr_accessor :interval
    # The earliest date to generate the report on (in ISO 8601 format).
    attr_accessor :start

    # The amount of time, in minutes, to allow execution before stopping.
    attr_accessor :max_duration
    # The date after which the schedule is disabled, in ISO 8601 format.
    attr_accessor :not_valid_after

    attr_accessor :incremental
    attr_accessor :repeater_type

    def initialize(type, interval, start, enabled = true)
      @type = type
      @interval = interval
      @start = start
      @enabled = enabled
    end

    def as_xml
      xml = REXML::Element.new('Schedule')
      xml.attributes['enabled'] = @enabled ? 1 : 0
      xml.attributes['type'] = @type
      xml.attributes['interval'] = @interval
      xml.attributes['start'] = @start
      xml.attributes['maxDuration'] = @max_duration if @max_duration
      xml.attributes['notValidAfter'] = @not_valid_after if @not_valid_after
      xml.attributes['incremental'] = @incremental ? 1 : 0 if @incremental
      xml.attributes['repeaterType'] = @repeater_type if @repeater_type
      xml
    end

    def to_xml
      as_xml.to_s
    end

    def self.parse(xml)
      schedule = Schedule.new(xml.attributes['type'],
                              xml.attributes['interval'].to_i,
                              xml.attributes['start'],
                              xml.attributes['enabled'] != '0')

      # Optional parameters.
      schedule.max_duration = xml.attributes['maxDuration'].to_i if xml.attributes['maxDuration']
      schedule.not_valid_after = xml.attributes['notValidAfter'] if xml.attributes['notValidAfter']
      schedule.incremental = (xml.attributes['incremental'] && xml.attributes['incremental'] == '1')
      schedule.repeater_type = xml.attributes['repeaterType'] if xml.attributes['repeaterType']
      schedule
    end

    # Recurring schedule type constants. These are all the possible values which
    # may be used to create a Schedule.
    #
    module Type
      DAILY = 'daily'
      HOURLY = 'hourly'
      WEEKLY = 'weekly'
      MONTHLY_DATE = 'monthly-date'
      MONTHLY_DAY = 'monthly-day'
    end
  end

  # Organization configuration, as used in Site and Silo.
  class Organization
    attr_accessor :name
    attr_accessor :url
    attr_accessor :primary_contact
    attr_accessor :job_title
    attr_accessor :email
    attr_accessor :telephone
    attr_accessor :address
    attr_accessor :state
    attr_accessor :city
    attr_accessor :zip
    attr_accessor :country

    def initialize(&block)
      instance_eval(&block) if block_given?
    end

    def self.parse(xml)
      new do |org|
        org.name = xml.attributes['name']
        org.url = xml.attributes['url']
        org.primary_contact = xml.attributes['primaryContact']
        org.job_title = xml.attributes['jobTitle']
        org.email = xml.attributes['email']
        org.telephone = xml.attributes['telephone']
        org.address = xml.attributes['businessAddress']
        org.state = xml.attributes['state']
        org.city = xml.attributes['city']
        org.zip = xml.attributes['zip']
        org.country = xml.attributes['country']
      end
    end

    def as_xml
      xml = REXML::Element.new('Organization')
      xml.add_attribute('name', @name)
      xml.add_attribute('url', @url)
      xml.add_attribute('primaryContact', @primary_contact)
      xml.add_attribute('jobTitle', @job_title)
      xml.add_attribute('email', @email)
      xml.add_attribute('telephone', @telephone)
      xml.add_attribute('businessAddress', @address)
      xml.add_attribute('state', @state)
      xml.add_attribute('city', @city)
      xml.add_attribute('zip', @zip)
      xml.add_attribute('country', @country)
      xml
    end
  end
end
