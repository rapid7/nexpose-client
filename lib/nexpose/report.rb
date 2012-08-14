module Nexpose
  module NexposeAPI
    include XMLUtils

    # Generate a new report using the specified report definition.
    def report_generate(report_id)
      xml = make_xml('ReportGenerateRequest', {'report-id' => report_id})
      ReportSummary.parse_all(execute(xml))
    end

    # Provide a history of all reports generated with the specified report
    # definition.
    def report_history(report_config_id)
      xml = make_xml('ReportHistoryRequest', {'reportcfg-id' => report_config_id})
      ReportSummary.parse_all(execute(xml))
    end

    # Get the details of the last report generated with the specified report id.
    def report_last(report_config_id)
      history = report_history(report_config_id)
      history.sort { |a, b| b.generated_on <=> a.generated_on }.first
    end

    # Delete a previously generated report definition.
    # Also deletes any reports generated from that configuration.
    def report_config_delete(report_config_id)
      xml = make_xml('ReportDeleteRequest', {'reportcfg-id' => report_config_id})
      execute(xml).success
    end

    # Delete a previously generated report.
    def report_delete(report_id)
      xml = make_xml('ReportDeleteRequest', {'report-id' => report_id})
      execute(xml).success
    end

    # Provide a list of all report templates the user can access on the
    # Security Console.
    #
    # Returns an array of maps containing:
    # * :template_id The ID of the report template.
    # * :name The name of the report template.
    # * :description Description of the report template.
    # * :scope The visibility (scope) of the report template. One of: global|silo
    # * :type One of: data|document. With a data template, you can export comma-separated value (CSV) files with vulnerability-based data. With a document template, you can create PDF, RTF, HTML, or XML reports with asset-based information.
    # --
    # FIXME API Guide says this is returned, but it isn't.
    # * :builtin Whether the report template is built-in, and therefore cannot be modified.
    # ++
    def report_template_listing
      r = execute(make_xml('ReportTemplateListingRequest', {}))
      templates = []
      if (r.success)
        r.res.elements.each('//ReportTemplateSummary') do |template|
          desc = ''
          template.elements.each('description') do |ent|
            desc = ent.text
          end

          templates << {
            :template_id => template.attributes['id'],
            :name => template.attributes['name'],
            :description => desc,
            :scope => template.attributes['scope'],
            :type => template.attributes['type']
            # :builtin => template.attributes['builtin']
          }
        end
      end
      templates
    end

    # Provide a listing of all report definitions the user can access on the
    # Security Console.
    #
    # Returns an array of maps containing:
    # * :template_id The ID of the report template.
    # * :cfg_id The report definition (config) ID.
    # * :status The current status of the report. One of: Started|Generated|Failed|Aborted|Unknown
    # * :generated_on The date and time the report was generated, in ISO 8601 format.
    # * :report_uri The URL to use to access the report.
    # * :scope One of: global|silo
    def report_listing
      r = execute(make_xml('ReportListingRequest', {}))
      reports = []
      if (r.success)
        r.res.elements.each('//ReportConfigSummary') do |report|
          reports << {
            :template_id => report.attributes['template-id'],
            :cfg_id => report.attributes['cfg-id'],
            :status => report.attributes['status'],
            :generated_on => report.attributes['generated-on'],
            :report_uri => report.attributes['report-URI'],
            # TODO Confirm scope is reported in multi-tenant environments.
            #      Always nil in single-tenant.
            :scope => report.attributes['scope']
          }
        end
      end
      reports
    end

    # Retrieve the configuration for a report definition.
    def get_report_config(report_config_id)
      xml = make_xml('ReportConfigRequest', {'reportcfg-id' => report_config_id})
      ReportConfig.parse(execute(xml))
    end
  end

  # --
  # === Description
  # Object that represents the summary of a Report Configuration.
  #
  # TODO Class appears to be unused. Values can be retrieved through
  # report_listing method above.
  # ++
  class ReportConfigSummary
    # The Report Configuration ID
    attr_reader :id
    # A unique name for the Report
    attr_reader :name
    # The report format
    attr_reader :format
    # The date of the last report generation
    attr_reader :last_generated_on
    # Relative URI of the last generated report
    attr_reader :last_generated_uri

    # Constructor
    def initialize(id, name, format, last_generated_on, last_generated_uri)
      @id = id
      @name = name
      @format = format
      @last_generated_on = last_generated_on
      @last_generated_uri = last_generated_uri
    end
  end

  # --
  # === Description
  # Object that represents the schedule on which to automatically generate new reports.
  # TODO Appears to be dead code. Report history can be grabbed through
  # report_history(report_config_id). This code requests the history,
  # but then doesn't even parse it until the xml_parse() method is invoked
  # with the very values it has been sitting on.
  # ++
  class ReportHistory
    # true if an error condition exists; false otherwise
    attr_reader :error
    # Error message string
    attr_reader :error_msg
    # The last XML request sent by this object
    attr_reader :request_xml
    # The last XML response received by this object
    attr_reader :response_xml
    # The NSC Connection associated with this object
    attr_reader :connection
    # The report definition (report config) ID
    # Report definition ID
    attr_reader :config_id
    # Array (ReportSummary*)
    attr_reader :report_summaries

    def initialize(connection, config_id)
      @error = false
      @connection = connection
      @config_id = config_id
      @report_summaries = []

      reportHistory_request = APIRequest.new('<ReportHistoryRequest session-id="' + "#{connection.session_id}" + '" reportcfg-id="' + "#{@config_id}" + '"/>', @connection.url)
      reportHistory_request.execute()
      @response_xml = reportHistory_request.response_xml
      @request_xml = reportHistory_request.request_xml
    end

    def xml_parse(response)
      response = REXML::Document.new(response.to_s)
      status = response.root.attributes['success']
      if (status == '1')
        @report_summaries = ReportSummary.parse_all(response)
      else
        @error = true
        @error_msg = 'Error ReportHistoryReponse'
      end
    end
  end

  # === Description
  # Summary of a single report.
  class ReportSummary
    # The id of the generated report.
    attr_reader :id
    # The report definition (configuration) ID.
    attr_reader :cfg_id
    # The current status of the report.
    # One of: Started|Generated|Failed|Aborted|Unknown
    attr_reader :status
    # The date and time the report was generated, in ISO 8601 format.
    attr_reader :generated_on
    # The relative URI to use to access the report.
    attr_reader :report_uri

    def initialize(id, cfg_id, status, generated_on, report_uri)
      @id = id
      @cfg_id = cfg_id
      @status = status
      @generated_on = generated_on
      @report_uri = report_uri
    end

    def self.parse(xml)
      ReportSummary.new(xml.attributes['id'], xml.attributes['cfg-id'], xml.attributes['status'], xml.attributes['generated-on'], xml.attributes['report-URI'])
    end

    def self.parse_all(response)
      summaries = []
      if (response.success)
        response.res.elements.each('//ReportSummary') do |summary|
          summaries << ReportSummary.parse(summary)
        end
      end
      summaries
    end
  end

  # === Description
  class ReportAdHoc
    include XMLUtils

    attr_reader :error
    attr_reader :error_msg
    attr_reader :connection
    # Report Template ID strong e.g. full-audit
    attr_reader :template_id
    # pdf|html|xml|text|csv|raw-xml
    attr_reader :format
    # Array of (Filter)*
    attr_reader :filters
    attr_reader :request_xml
    attr_reader :response_xml
    attr_reader :report_decoded

    def initialize(connection, template_id = 'full-audit', format = 'raw-xml')
      @error = false
      @connection = connection
      @filters = []
      @template_id = template_id
      @format = format
    end

    def addFilter(filter_type, id)
      # filter_type can be site|group|device|scan
      # id is the ID number. For scan, you can use 'last' for the most recently run scan
      filter = Filter.new(filter_type, id)
      filters.push(filter)
    end

    def generate()
      request_xml = '<ReportAdhocGenerateRequest session-id="' + @connection.session_id + '">'
      request_xml += '<AdhocReportConfig template-id="' + @template_id + '" format="' + @format + '">'
      request_xml += '<Filters>'
      @filters.each do |f|
        request_xml += '<filter type="' + f.type + '" id="'+ f.id.to_s + '"/>'
      end
      request_xml += '</Filters>'
      request_xml += '</AdhocReportConfig>'
      request_xml += '</ReportAdhocGenerateRequest>'

      ad_hoc_request = APIRequest.new(request_xml, @connection.url)
      ad_hoc_request.execute()

      content_type_response = ad_hoc_request.raw_response.header['Content-Type']
      if content_type_response =~ /multipart\/mixed;\s*boundary=([^\s]+)/
        # Nexpose sends an incorrect boundary format which breaks parsing
        # Eg: boundary=XXX; charset=XXX
        # Fix by removing everything from the last semi-colon onward
        last_semi_colon_index = content_type_response.index(/;/, content_type_response.index(/boundary/))
        content_type_response = content_type_response[0, last_semi_colon_index]

        data = "Content-Type: " + content_type_response + "\r\n\r\n" + ad_hoc_request.raw_response_data
        doc = Rex::MIME::Message.new data
        doc.parts.each do |part|
          if /.*base64.*/ =~ part.header.to_s
            if (@format == "text") or (@format == "pdf") or (@format == "csv")
              return part.content.unpack("m*")[0]
            else
              return parse_xml(part.content.unpack("m*")[0])
            end
          end
        end
      end
    end
  end

  # === Description
  # Object that represents the configuration of a report definition.
  class ReportConfigX
    # true if an error condition exists; false otherwise
    attr_reader :error
    # Error message string
    attr_reader :error_msg
    # The last XML request sent by this object
    attr_reader :request_xml
    # The last XML response received by this object
    attr_reader :response_xml
    # The NSC Connection associated with this object
    attr_reader :connection
    # The ID for this report definition
    attr_reader :config_id
    # A unique name for this report definition
    attr_reader :name
    # The template ID used for this report definition
    attr_reader :template_id
    # html, db, txt, xml, raw-xml, csv, pdf
    attr_reader :format
    # XXX new
    attr_reader :timezone
    # XXX new
    attr_reader :owner
    # Array of (Filter)* - The Sites, Asset Groups, or Devices to run the report against
    attr_reader :filters
    # Automatically generate a new report at the conclusion of a scan
    # 1 or 0
    attr_reader :generate_after_scan
    # Schedule to generate reports
    # ReportSchedule Object
    attr_reader :schedule
    # Store the reports on the server
    # 1 or 0
    attr_reader :storeOnServer
    # Location to store the report on the server
    attr_reader :store_location
    # Form to send the report via email
    # "file", "zip", "url", or NULL (don’t send email)
    attr_reader :email_As
    # Send the Email to all Authorized Users
    # boolean - Send the Email to all Authorized Users
    attr_reader :email_to_all
    # Array containing the email addresses of the recipients
    attr_reader :email_recipients
    # IP Address or Hostname of SMTP Relay Server
    attr_reader :smtp_relay_server
    # Sets the FROM field of the Email
    attr_reader :sender
    # TODO
    attr_reader :db_export
    # TODO
    attr_reader :csv_export
    # TODO
    attr_reader :xml_export

    def initialize(connection, config_id = -1)
      @error = false
      @connection = connection
      @config_id = config_id
      @xml_tag_stack = []
      @filters = []
      @email_recipients = []
      @name = "New Report " + rand(999999999).to_s

      r = @connection.execute('<ReportConfigRequest session-id="' + @connection.session_id.to_s + '" reportcfg-id="' + @config_id.to_s + '"/>')
      if (r.success)
        r.res.elements.each('ReportConfigResponse/ReportConfig') do |r|
          @name = r.attributes['name']
          @format = r.attributes['format']
          @timezone = r.attributes['timezone']
          @id = r.attributes['id']
          @template_id = r.attributes['template-id']
          @owner = r.attributes['owner']
        end
      else
        @error = true
        @error_msg = 'Error ReportHistoryReponse'
      end
    end

    # === Description
    # Generate a new report on this report definition. Returns the new report ID.
    def generateReport(debug = false)
      return generateReport(@connection, @config_id, debug)
    end

    # === Description
    # Save the report definition to the NSC.
    # Returns the config-id.
    def saveReport()
      r = @connection.execute('<ReportSaveRequest session-id="' + @connection.session_id.to_s + '">' + getXML().to_s + ' </ReportSaveRequest>')
      if (r.success)
        @config_id = r.attributes['reportcfg-id']
        return true
      end
      return false
    end

    # === Description
    # Adds a new filter to the report config
    def addFilter(filter_type, id)
      filter = Filter.new(filter_type, id)
      @filters.push(filter)
    end

    # === Description
    # Adds a new email recipient
    def addEmailRecipient(recipient)
      @email_recipients.push(recipient)
    end

    # === Description
    # Sets the schedule for this report config
    def setSchedule(schedule)
      @schedule = schedule
    end

    def getXML()
      xml = '<ReportConfig id="' + @config_id.to_s + '" name="' + @name.to_s + '" template-id="' + @template_id.to_s + '" format="' + @format.to_s + '">'

      xml += ' <Filters>'
      @filters.each do |f|
        xml += ' <filter type="' + f.type.to_s + '" id="' + f.id.to_s + '"/>'
      end
      xml += ' </Filters>'

      xml += ' <Generate after-scan="' + @generate_after_scan.to_s + '">'
      if (@schedule)
        xml += ' <Schedule type="' + @schedule.type.to_s + '" interval="' + @schedule.interval.to_s + '" start="' + @schedule.start.to_s + '"/>'
      end
      xml += ' </Generate>'

      xml += ' <Delivery>'
      xml += ' <Storage storeOnServer="' + @storeOnServer.to_s + '">'
      if (@store_location and @store_location.length > 0)
        xml += ' <location>' + @store_location.to_s + '</location>'
      end
      xml += ' </Storage>'
      xml += ' </Delivery>'

      xml += ' </ReportConfig>'
      return xml
    end

    def set_name(name)
      @name = name
    end

    def set_template_id(template_id)
      @template_id = template_id
    end

    def set_format(format)
      @format = format
    end

    def set_email_As(email_As)
      @email_As = email_As
    end

    def set_storeOnServer(storeOnServer)
      @storeOnServer = storeOnServer
    end

    def set_smtp_relay_server(smtp_relay_server)
      @smtp_relay_server = smtp_relay_server
    end

    def set_sender(sender)
      @sender = sender
    end

    def set_generate_after_scan(generate_after_scan)
      @generate_after_scan = generate_after_scan
    end
  end

  # Definition object for a report configuration.
  class ReportConfig
    # The ID of the report definition (config).
    # Use -1 to create a new definition.
    attr_accessor :id
    # The unique name assigned to the report definition.
    attr_accessor :name
    # The ID of the report template used.
    attr_accessor :template_id
    # Format. One of: pdf|html|rtf|xml|text|csv|db|raw-xml|raw-xml-v2|ns-xml|qualys-xml
    attr_accessor :format
    attr_accessor :owner
    attr_accessor :timezone

    # Description associated with this report.
    attr_accessor :description
    # Array of filters associated with this report.
    attr_accessor :filters
    # Array of user IDs which have access to resulting reports.
    attr_accessor :users
    # Baseline comparison highlights the changes between two scans, including
    # newly discovered assets, services and vulnerabilities, assets and services
    # that are no longer available and vulnerabilities that were mitigated or
    # fixed. The current scan results can be compared against the results of the
    # first scan, the most recent (previous) scan, or the scan results from a
    # particular date.
    attr_accessor :baseline
    # Configuration of when a report is generated.
    attr_accessor :generate
    # Report delivery configuration.
    attr_accessor :delivery
    # Database export configuration.
    attr_accessor :db_export

    # Construct a basic ReportConfig object.
    def initialize(id, name, template_id, format, owner, timezone)
      @id = id
      @name = name
      @template_id = template_id
      @format = format
      @owner = owner
      @timezone = timezone

      @filters = []
      @users = []
    end

    # Retrieve the configuration for an existing report definition.
    def self.get(connection, report_config_id)
      connection.get_report_config(report_config_id)
    end

    # Save the configuration of this report definition.
    def save(connection, generate_now = false)
      xml = %Q{<ReportSaveRequest session-id='#{connection.session_id}' generate-now='#{generate_now ? 1 : 0}'>}
      xml << to_xml
      xml << '</ReportSaveRequest>'
      response = connection.execute(xml)
      if response.success
        @id = response.attributes['reportcfg-id']
      end
    end

    # Generate a new report using this report definition.
    def generate(connection)
      connection.report_generate(@id)
    end

    # Delete this report definition from the Security Console.
    # Deletion will also remove all reports previously generated from the
    # configuration.
    def delete(connection)
      connection.report_config_delete(@id)
    end

    def to_xml
      xml = %Q{<ReportConfig format='#{@format}' id='#{@id}' name='#{@name}' owner='#{@owner}' template-id='#{@template_id}' timezone='#{@timezone}'>}
      xml << %Q{<description>#{@description}</description>} if @description

      xml << '<Filters>'
      @filters.each { |filter| xml << filter.to_xml }
      xml << '</Filters>'

      xml << '<Users>'
      @users.each { |user| xml << %Q{<user id='#{user}' />} }
      xml << '</Users>'

      xml << %Q{<Baseline compareTo='#{@baseline}' />} if @baseline
      xml << @generate.to_xml if @generate
      xml << @delivery.to_xml if @delivery
      xml << @db_export.to_xml if @db_export

      xml << '</ReportConfig>'
    end

    def self.parse(xml)
      xml.res.elements.each('//ReportConfig') do |cfg|
        config = ReportConfig.new(cfg.attributes['id'],
                                  cfg.attributes['name'],
                                  cfg.attributes['template-id'],
                                  cfg.attributes['format'],
                                  cfg.attributes['owner'],
                                  cfg.attributes['timezone'])

        cfg.elements.each('//description') do |desc|
          config.description = desc.text
        end

        config.filters = Filter.parse(xml)

        cfg.elements.each('//user') do |user|
          config.users << user.attributes['id'].to_i
        end

        cfg.elements.each('//Baseline') do |baseline|
          config.baseline = baseline.attributes['compareTo']
        end

        config.generate = Generate.parse(cfg)
        config.delivery = Delivery.parse(cfg)
        config.db_export = DBExport.parse(cfg)

        return config
      end
      nil
    end
  end

  # === Description
  # Object that represents a report filter which determines which sites, asset
  # groups, and/or devices that a report is run against.  gtypes are
  # "SiteFilter", "AssetGroupFilter", "DeviceFilter", or "ScanFilter".  gid is
  # the site-id, assetgroup-id, or devce-id.  ScanFilter, if used, specifies
  # a specifies a specific scan to use as the data source for the report. The gid
  # can be a specific scan-id or "first" for the first run scan, or “last” for
  # the last run scan.
  class Filter
    # The ID of the specific site, group, device, or scan.
    # For scan, this can also be "last" for the most recently run scan.
    # For vuln-status, the ID can have one of the following values:
    # 1. vulnerable-exploited (The check was positive. An exploit verified the vulnerability.)
    # 2. vulnerable-version (The check was positive. The version of the scanned service or software is associated with known vulnerabilities.)
    # 3. potential (The check for a potential vulnerability was positive.)
    # These values are supported for CSV and XML formats.
    attr_reader :id
    # One of: site|group|device|scan|vuln-categories|vuln-severity|vuln-status|cyberscope-component|cyberscope-bureau|cyberscope-enclave
    attr_reader :type

    def initialize(type, id)
      @type = type
      @id = id
    end

    def to_xml
      %Q{<filter id='#{@id}' type='#{@type}' />}
    end

    def self.parse(xml)
      filters = []
      xml.res.elements.each('//Filters/filter') do |filter|
        filters << Filter.new(filter.attributes['type'], filter.attributes['id']) 
      end
      filters
    end
  end

  # Data object associated with when a report is generated
  class Generate
    # Will the report be generated after a scan completes (1),
    # or is it ad-hoc/scheduled (0).
    attr_accessor :after_scan
    # Whether or not a scan is scheduled (0|1).
    attr_accessor :scheduled
    # Schedule associated with the report.
    attr_accessor :schedule

    def initialize(after_scan, scheduled, schedule = nil)
      @after_scan = after_scan
      @scheduled = scheduled
      @schedule = schedule
    end

    def to_xml
      xml = %Q{<Generate after-scan='#{@after_scan ? 1 : 0}' schedule='#{@scheduled ? 1 : 0}'>}
      xml << @schedule.to_xml if @schedule
      xml << '</Generate>'
    end

    def self.parse(xml)
      xml.elements.each('//Generate') do |generate|
        if generate.attributes['after-scan'] == '1'
          return Generate.new(true, false)
        else
          if generate.attributes['schedule'] == '1'
            schedule = Schedule.parse(xml)
            return Generate.new(false, true, schedule)
          end
          return Generate.new(false, false)
        end
      end
      nil
    end
  end

  # Data object for configuration of where a report is stored or delivered.
  class Delivery
    # Whether to store report on server.
    attr_accessor :store_on_server
    # Directory location to store report in (for non-default storage).
    attr_accessor :location
    # E-mail configuration.
    attr_accessor :email

    def initialize(store_on_server, location = nil, email = nil)
      @store_on_server = store_on_server
      @location = location
      @email = email
    end

    def to_xml
      xml = '<Delivery>'
      xml << %Q{<Storage storeOnServer='#{@store_on_server ? 1 : 0}'>}
      xml << %Q{<location>#{@location}</location>} if @location
      xml << '</Storage>'
      xml << @email.to_xml if @email
      xml << '</Delivery>'
    end

    def self.parse(xml)
      xml.elements.each('//Delivery') do |delivery|
        on_server = false
        location = nil
        xml.elements.each('//Storage') do |storage|
          on_server = true if storage.attributes['storeOnServer'] == '1'
          xml.elements.each('//location') do |loc|
            location = loc.text
          end
        end

        email = Email.parse(xml)

        return Delivery.new(on_server, location, email)
      end
      nil
    end
  end

  # Configuration structure for database exporting of reports.
  class DBExport
    # The DB type to export to.
    attr_accessor :type
    # Credentials needed to export to the specified database.
    attr_accessor :credentials
    # Map of parameters for this DB export configuration.
    attr_accessor :parameters

    def initialize(type)
      @type = type
      @parameters = {}
    end

    def to_xml
      xml = %Q{<DBExport type='#{@type}'>}
      xml << @credentials.to_xml if @credentials
      @parameters.each_pair do |name, value|
        xml << %Q{<param name='#{name}'>#{value}</param>}
      end
      xml << '</DBExport>'
    end

    def self.parse(xml)
      xml.elements.each('//DBExport') do |dbexport|
        config = DBExport.new(dbexport.attributes['type'])
        config.credentials = ExportCredential.parse(xml) 
        xml.elements.each('//param') do |param|
          config.parameters[param.attributes['name']] = param.text
        end
        return config
      end
      nil
    end
  end

  # DBExport credentials configuration object.
  #
  # The userid, password and realm attributes should ONLY be used
  # if a security blob cannot be generated and the data is being
  # transmitted/stored using external encryption (e.g., HTTPS).
  class ExportCredential
    # Security blob for exporting to a database.
    attr_accessor :credential
    attr_accessor :userid
    attr_accessor :password
    # DB specific, usually the database name.
    attr_accessor :realm

    def initialize(credential)
      @credential = credential
    end

    def to_xml
      xml = '<credentials'
      xml << %Q{ userid='#{@userid}'} if @userid
      xml << %Q{ password='#{@password}'} if @password
      xml << %Q{ realm='#{@realm}'} if @realm
      xml << '>'
      xml << @credential if @credential
      xml << '</credentials>'
    end

    def self.parse(xml)
      xml.elements.each('//credentials') do |creds|
        credential = ExportCredential.new(creds.text)
        # The following attributes may not exist.
        credential.userid = creds.attributes['userid']
        credential.password = creds.attributes['password']
        credential.realm = creds.attributes['realm']
        return credential
      end
      nil
    end
  end

  # --
  # TODO Generic Schedule class exists.
  #
  # === Description
  # Object that represents the schedule on which to automatically generate new reports.
  # ++
  class ReportSchedule
    # The type of schedule
    # (daily, hourly, monthly, weekly)
    attr_reader :type
    # The frequency with which to run the scan
    attr_reader :interval
    # The earliest date to generate the report
    attr_reader :start

    def initialize(type, interval, start)
      @type = type
      @interval = interval
      @start = start
    end
  end

  # --
  # TODO: Class duplicates functionality of report_template_listing call.
  #       Should be removed if it doesn't add additional value.
  # ++
  class ReportTemplateListing
    attr_reader :error_msg
    attr_reader :error
    attr_reader :request_xml
    attr_reader :response_xml
    attr_reader :connection
    attr_reader :xml_tag_stack
    attr_reader :report_template_summaries #;  //Array (ReportTemplateSummary*)

    def initialize(connection)
      @error = nil
      @connection = connection
      @report_template_summaries = []

      r = @connection.execute('<ReportTemplateListingRequest session-id="' + connection.session_id.to_s + '"/>')
      if (r.success)
        r.res.elements.each('ReportTemplateListingResponse/ReportTemplateSummary') do |r|
          @report_template_summaries.push(ReportTemplateSummary.new(r.attributes['id'], r.attributes['name'], r.attributes['description']))
        end
      else
        @error = true
        @error_msg = 'ReportTemplateListingRequest Parse Error'
      end
    end
  end

  # --
  # TODO Same functionality in report_listing method.
  # ++
  class ReportListing
    attr_reader :error_msg
    attr_reader :error
    attr_reader :request_xml
    attr_reader :response_xml
    attr_reader :connection
    attr_reader :xml_tag_stack
    attr_reader :report_summaries #; //Array (ReportSummary*)

    def initialize(connection)
      @error = nil
      @connetion = connection
      @report_summaries = []

      r = @connetion.execute('<ReportListingRequest session-id="' + connection.session_id.to_s + '"/>')
      if (r.success)
        r.res.elements.each('ReportListingResponse/ReportConfigSummary') do |r|
          # Note that this does record 'scope', which is in ReportConfigSummary, but not ReportSummary
          @report_summaries.push(ReportSummary.new(r.attributes['template-id'], r.attributes['cfg-id'], r.attributes['status'], r.attributes['generated-on'], r.attributes['report-URI']))
        end
      else
        @error = true
        @error_msg = 'ReportListingRequest Parse Error'
      end
    end
  end

  # --
  # TODO: Is this class useful? Summaries produced by report_template_listing.
  # ++
  class ReportTemplateSummary
    attr_reader :id
    attr_reader :name
    attr_reader :description

    def initialize(id, name, description)
      @id = id
      @name = name
      @description = description
    end
  end

  class ReportSection
    attr_reader :name
    attr_reader :properties

    def initialize(name)
      @properties = []
      @name = name
    end

    def addProperty(name, value)
      @properties[name.to_s] = value
    end
  end
end
