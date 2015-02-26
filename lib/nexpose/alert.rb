module Nexpose

  class ScanFilter
    include JsonSerializer
    # Scan events to alert on.
    attr_accessor :start, :stop, :fail, :resume, :pause

    def initialize(start = 0, stop = 0, fail = 0, resume = 0, pause = 0)
      @start, @stop, @fail, @resume, @pause = start, stop, fail, resume, pause
    end

    def self.json_initializer(filter)
      new(filter[:start], filter[:stop], filter[:failed], filter[:resume], filter[:pause])
    end
  end

  class VulnFilter
    include JsonSerializer
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

    def self.json_initializer(filter)
      new(filter[:severity], filter[:unconfirmed], filter[:confirmed], filter[:potential])
    end
  end

  # Alert parent object.
  # The three alert types should be wrapped in this object to store data.
  #
  module Alert
    include JsonSerializer
    extend TypedAccessor

    # ID for this alert.
    attr_accessor :id
    # Name for this alert.
    attr_accessor :name
    # Whether or not this alert is currently active.
    attr_accessor :enabled
    # Send at most this many alerts per scan.
    attr_accessor :max_alerts
    # Send alerts based upon scan status.
    #JsonSerializer.typed_accessor :scan_filter, ScanFilter
    # Send alerts based upon vulnerability finding status.
    #attr_accessor :vuln_filter
    # Alert type and its configuration. One of SMTPAlert, SyslogAlert, SNMPAlert
    attr_accessor :alert_type
    attr_accessor :severity_threshold

    typed_accessor :scan_filter, ScanFilter
    typed_accessor :vuln_filter, VulnFilter

    # def initialize(name, enabled = 1, max_alerts = -1)
    #   @name, @enabled, @max_alerts = name, enabled, max_alerts
    # end

    def self.load(nsc, site_id, alert_id)
      uri = "/api/2.1/site_configurations/#{site_id}/alerts/#{alert_id}"
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)

      unless resp.to_s == ''
        data = JSON.parse(resp, symbolize_names: true)

        json_initializer(data).deserialize(data)

        # alerts = self.load_alerts([data])
        #
        # unless alerts.empty?
        #   alerts[0]
        # end
      end
    end

    def self.load_alerts(alerts)
      alerts.map {|hash| json_initializer(hash).deserialize(hash) }
      # unless alerts.nil?
      #   alerts = alerts.map do |hash|
      #     alert = self.create(hash)
      #
      #     alert.id = hash[:id]
      #     alert.name = hash[:name]
      #     alert.enabled = hash[:enabled]
      #     alert.max_alerts = hash[:max_alerts]
      #     scan_filter = hash[:scan_filter]
      #     vuln_filter = hash[:vuln_filter]
      #     alert.scan_filter = ScanFilter.new(scan_filter[:scan_start], scan_filter[:scan_stop], scan_filter[:scan_failed], scan_filter[:scan_resume], scan_filter[:scan_pause])
      #     alert.vuln_filter = VulnFilter.new(vuln_filter[:severity], vuln_filter[:unconfirmed], vuln_filter[:confirmed], vuln_filter[:potential])
      #     alert
      #   end
      # end
      #alerts
    end

    def self.list_alerts(nsc, id)
      uri = "/api/2.1/site_configurations/#{id}/alerts"
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      data = JSON.parse(resp, symbolize_names: true)

      unless data.nil?
        alerts = self.load_alerts(data)
      end
    end

    def self.json_initializer(hash)
      create(hash)
    end

    def to_h
      to_hash(Hash.new)

      # {
      #     id: id,
      #     name: name,
      #     enabled: enabled,
      #     severity_threshold: severity_threshold,
      #     scan_filter: filter_to_h()
      # }
    end

    def filter_to_h
      {
          max_alerts: max_alerts,
          scan_start: scan_filter.start,
          scan_stop: scan_filter.stop,
          scan_failed: scan_filter.fail,
          scan_pause: scan_filter.pause,
          scan_resume: scan_filter.resume,
          vulnerability_exploit: vuln_filter.unconfirmed,
          vulnerability_version: vuln_filter.confirmed,
          vulnerability_potential: vuln_filter.potential
      }
    end

    def to_json
      serialize()
      #JSON.generate(to_h)
    end

    def delete(nsc, site_id)
      uri = "/api/2.1/site_configurations/#{site_id}/alerts/#{self.id}"
      AJAX.delete(nsc, uri, AJAX::CONTENT_TYPE::JSON)
    end

    def save(nsc, site_id)
      validate
      uri = "/api/2.1/site_configurations/#{site_id}/alerts"
      id = AJAX.put(nsc, uri, self.to_json, AJAX::CONTENT_TYPE::JSON)
      @id = id.to_i
    end

    def validate()
      raise ArgumentError.new('Name is a required attribute.') unless @name
      raise ArgumentError.new('Scan filter is a required attribute.') unless @scan_filter
      raise ArgumentError.new('Vuln filter is a required attribute.') unless @vuln_filter
    end

    private
    def self.create(hash)
      if !hash.has_key?(:name) || hash[:name].to_s == ''
        raise 'Alert name cannot be empty.'
      end

      alert_type = hash[:alert_type]

      if alert_type.nil?
        raise 'An alert must have an alert type'
      end

      if ['SNMP', 'Syslog'].include?(alert_type) && hash[:server].to_s == ''
        raise 'SNMP and Syslog alerts must have a server defined'
      end

      case alert_type
        when 'SMTP'
          alert = SMTPAlert.new(hash[:name], hash[:sender], hash[:server], hash[:recipients], hash[:enabled], hash[:max_alerts], hash[:verbose])
        when 'SNMP'
          alert = SNMPAlert.new(hash[:name], hash[:community], hash[:server],  hash[:enabled], hash[:max_alerts])
        when 'Syslog'
          alert = SyslogAlert.new(hash[:name], hash[:server], hash[:enabled], hash[:max_alerts])
        else
          fail "Unknown alert type: #{alert_type}"
      end
      alert.scan_filter = ScanFilter.new
      alert.vuln_filter = VulnFilter.new

      alert
    end
  end

  class SMTPAlert #< Alert
    include Alert
    attr_accessor :recipients, :sender, :verbose, :server

    def initialize(name, sender, server, recipients, enabled = 1, max_alerts = -1, verbose = 0)
      unless recipients.is_a?(Array) && recipients.length > 0
        raise 'An SMTP alert must contain an array of recipient emails with at least 1 recipient'
      end

      recipients.each do  |recipient|
        unless recipient =~ /^.+@.+\..+$/
          raise "Recipients must contain valid emails, #{recipient} has an invalid format"
        end
      end

      @alert_type = 'SMTP'
      @name = name
      @enabled = enabled
      @max_alerts = max_alerts
      @sender = sender
      @server = server
      @verbose = verbose
      @recipients = recipients.nil? ? []: recipients
    end

    # def to_h()
    #   {
    #       alert_type: alert_type,
    #       sender: sender,
    #       server: server,
    #       limit_text: verbose,
    #       recipients: recipients
    #   }.merge(super.to_h)
    # end

    def add_email_recipient(recipient)
      @recipients << recipient
    end

    def remove_email_recipient(recipient)
      @recipients.delete(recipient)
    end
  end

  class SNMPAlert #< Alert
    include Alert
    attr_accessor :community, :server

    def initialize(name, community, server, enabled = 1, max_alerts = -1)
      @alert_type = 'SNMP'
      if community.nil?
        raise 'SNMP alerts must have a community defined.'
      end
      @name = name
      @enabled = enabled
      @max_alerts = max_alerts
      @community = community
      @server = server
    end

    # def to_h()
    #   {
    #       alert_type: alert_type,
    #       community: community,
    #       server: server
    #   }.merge(super.to_h)
    # end
  end

  class SyslogAlert #< Alert
    include Alert
    attr_accessor :server

    def initialize(name, server, enabled = 1, max_alerts = -1)
      @alert_type = 'Syslog'
      @name = name
      @enabled = enabled
      @max_alerts = max_alerts
      @server = server
    end

    # def to_h()
    #   {
    #       alert_type: alert_type,
    #       server: server
    #   }.merge(super.to_h)
    # end
  end
end