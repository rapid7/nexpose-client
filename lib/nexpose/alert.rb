module Nexpose

  # Alert parent object.
  # The three alert types should be wrapped in this object to store data.
  #
  class Alert

    # Name for this alert.
    attr_accessor :name
    # Whether or not this alert is currently active.
    attr_accessor :enabled
    # Send at most this many alerts per scan.
    attr_accessor :max_alerts
    # Send alerts based upon scan status.
    attr_accessor :scan_filter
    # Send alerts based upon vulnerability finding status.
    attr_accessor :vuln_filter
    # Alert type and its configuration. One of SMTPAlert, SyslogAlert, SNMPAlert
    attr_accessor :type

    def initialize(name, enabled = 1, max_alerts = -1)
      @name, @enabled, @max_alerts = name, enabled, max_alerts
    end

    def to_xml
      xml = '<Alert'
      xml << %( name="#{@name}")
      xml << %( enabled="#{@enabled}")
      xml << %( maxAlerts="#{@max_alerts}")
      xml << '>'
      xml << scan_filter.to_xml
      xml << vuln_filter.to_xml
      xml << type.to_xml
      xml << '</Alert>'
    end

    # Parse a response from a Nexpose console into a valid Alert object.
    #
    # @param [REXML::Document] rexml XML document to parse.
    # @return [Alert] Alert object represented by the XML.
    #
    def self.parse(rexml)
      name = rexml.attributes['name']
      rexml.elements.each("//Alert[@name='#{name}']") do |xml|
        alert = new(name,
                    xml.attributes['enabled'].to_i,
                    xml.attributes['maxAlerts'].to_i)
        alert.scan_filter = ScanFilter.parse(REXML::XPath.first(xml, "//Alert[@name='#{name}']/scanFilter"))
        alert.vuln_filter = VulnFilter.parse(REXML::XPath.first(xml, "//Alert[@name='#{name}']/vulnFilter"))
        if (type = REXML::XPath.first(xml, "//Alert[@name='#{name}']/smtpAlert"))
          alert.type = SMTPAlert.parse(type)
        elsif (type = REXML::XPath.first(xml, "//Alert[@name='#{name}']/syslogAlert"))
          alert.type = SyslogAlert.parse(type)
        elsif (type = REXML::XPath.first(xml, "//Alert[@name='#{name}']/snmpAlert"))
          alert.type = SNMPAlert.parse(type)
        end
        return alert
      end
      nil
    end
  end

  # Scan filter for alerting.
  # Set values to 1 to enable and 0 to disable.
  #
  class ScanFilter
    # Scan events to alert on.
    attr_accessor :start, :stop, :fail, :resume, :pause

    def initialize(start = 0, stop = 0, fail = 0, resume = 0, pause = 0)
      @start, @stop, @fail, @resume, @pause = start, stop, fail, resume, pause
    end

    def to_xml
      xml = '<scanFilter'
      xml << %( scanStart="#{@start}")
      xml << %( scanStop="#{@stop}")
      xml << %( scanFailed="#{@fail}")
      xml << %( scanResumed="#{@resume}")
      xml << %( scanPaused="#{@pause}")
      xml << '/>'
    end

    def self.parse(xml)
      new(xml.attributes['scanStart'].to_i,
          xml.attributes['scanStop'].to_i,
          xml.attributes['scanFailed'].to_i,
          xml.attributes['scanResumed'].to_i,
          xml.attributes['scanPaused'].to_i)
    end
  end

  # Vulnerability filtering for alerting.
  # Set values to 1 to enable and 0 to disable.
  #
  class VulnFilter

    # Only alert on vulnerability findings with a severity level greater than this level.
    # Range is 0 to 10.
    # Values in the UI correspond as follows:
    #   Any severity: 1
    #   Severe and critical: 4
    #   Only critical: 8
    attr_accessor :severity

    # Vulnerability events to alert on.
    attr_accessor :confirmed, :unconfirmed, :potential

    def initialize(severity = 1, confirmed = 1, unconfirmed = 1, potential = 1)
      @severity, @confirmed, @unconfirmed, @potential = severity, confirmed, unconfirmed, potential
    end

    def to_xml
      xml = '<vulnFilter'
      xml << %( severityThreshold="#{@severity}")
      xml << %( confirmed="#{@confirmed}")
      xml << %( unconfirmed="#{@unconfirmed}")
      xml << %( potential="#{@potential}")
      xml << '/>'
    end

    def self.parse(xml)
      new(xml.attributes['severityThreshold'].to_i,
          xml.attributes['confirmed'].to_i,
          xml.attributes['unconfirmed'].to_i,
          xml.attributes['potential'].to_i)
    end
  end

  # Syslog Alert
  # This class should only exist as an element of an Alert.
  #
  class SyslogAlert

    # The server to sent this alert to.
    attr_accessor :server

    def initialize(server)
      @server = server
    end

    def self.parse(xml)
      new(xml.attributes['server'])
    end

    include Sanitize

    def to_xml
      xml = '<syslogAlert'
      xml << %( server="#{replace_entities(server)}">)
      xml << '</syslogAlert>'
    end
  end

  # SNMP Alert
  # This class should only exist as an element of an Alert.
  #
  class SNMPAlert

    # The community string
    attr_accessor :community

    # The server to sent this alert
    attr_accessor :server

    def initialize(community, server)
      @community = community
      @server = server
    end

    def self.parse(xml)
      new(xml.attributes['community'], xml.attributes['server'])
    end

    include Sanitize

    def to_xml
      xml = '<snmpAlert'
      xml << %( community="#{replace_entities(community)}")
      xml << %( server="#{replace_entities(server)}">)
      xml << '</snmpAlert>'
    end
  end

  # SMTP (e-mail) Alert
  # This class should only exist as an element of an Alert.
  #
  class SMTPAlert

    # The e-mail address of the sender.
    attr_accessor :sender
    # The server to sent this alert.
    attr_accessor :server
    # Limit the text for mobile devices.
    attr_accessor :limit_text
    # Array of strings with the e-mail addresses of the intended recipients.
    attr_accessor :recipients

    def initialize(sender, server, limit_text = 0)
      @sender = sender
      @server = server
      @limit_text = limit_text
      @recipients = []
    end

    # Adds a new recipient to the alert.
    def add_recipient(recipient)
      @recipients << recipient
    end

    include Sanitize

    def to_xml
      xml = '<smtpAlert'
      xml << %( sender="#{replace_entities(sender)}")
      xml << %( server="#{replace_entities(server)}")
      xml << %( limitText="#{limit_text}">)
      recipients.each do |recpt|
        xml << "<recipient>#{replace_entities(recpt)}</recipient>"
      end
      xml << '</smtpAlert>'
    end

    def self.parse(xml)
      alert = new(xml.attributes['sender'], xml.attributes['server'], xml.attributes['limitText'].to_i)
      xml.elements.each("//recipient") do |recipient|
        alert.recipients << recipient.text
      end
      alert
    end
  end
end
