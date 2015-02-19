module Nexpose

  # Alert parent object.
  # The three alert types should be wrapped in this object to store data.
  #
  class Alert < APIObject
    include JsonSerializer
    # ID for this alert.
    attr_accessor :id

    # Name for this alert.
    attr_accessor :name
    # Whether or not this alert is currently active.
    attr_accessor :enabled

    # Send alerts based upon scan status.
    attr_accessor :scan_filter
    # Send alerts based upon vulnerability finding status.
    attr_accessor :vuln_filter
    # Alert type and its configuration. One of SMTPAlert, SyslogAlert, SNMPAlert
    attr_accessor :type
    # The level of error severity to be met before creating alert
    attr_accessor :severity_threshold
    # The alert type
    attr_accessor :alert_type
    # The alert server
    attr_accessor :server

    def self.list_alerts(nsc, id)
      uri = "/api/2.1/sites/#{id}/configuration/alerts"
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      data = JSON.parse(resp, symbolize_names: true)

      alerts = []
      data.each { |a| alerts << new.deserialize(a) }

      alerts
    end

    def get_max_alerts
      unless self.scan_filter.nil?
        max_alerts = self.scan_filter['max_alerts']
      else
        max_alerts = -1
      end

      max_alerts
    end
  end

  class ScanFilter
    include JsonSerializer

    attr_accessor :scan_start, :scan_pause, :scan_fail, :scan_resume, :scan_stop
    attr_accessor :vulnerability_exploit, :vulnerability_version, :vulnerability_potential
  end

  class SMTPAlert < Alert
    attr_accessor :recipients, :sender, :verbose

    def initialize(verbose = true)
      @alert_type = 'SMTP'
      @recipients = Set.new
      @verbose = verbose
    end

    def add_email_recipient(recipient)
      @recipients << recipient
    end

    def remove_email_recipient(recipient)
      @recipients.delete(recipient)
    end
  end

  class SNMP < Alert
    attr_accessor :community

    def initialize()
      @alert_type = 'SNMP'
    end
  end

  class SNMP < Alert
    def initialize()
      @alert_type = 'Syslog'
    end
  end
end