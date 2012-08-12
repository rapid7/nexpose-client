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
  end

  # === Description
  # Object that represents the summary of a Report Configuration.
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

  # === Description
  # Object that represents the schedule on which to automatically generate new reports.
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
    # Array of (ReportFilter)*
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
      filter = ReportFilter.new(filter_type, id)
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
  class ReportConfig
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
    # Array of (ReportFilter)* - The Sites, Asset Groups, or Devices to run the report against
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
      filter = ReportFilter.new(filter_type, id)
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

  # === Description
  # Object that represents a report filter which determines which sites, asset
  # groups, and/or devices that a report is run against.  gtypes are
  # "SiteFilter", "AssetGroupFilter", "DeviceFilter", or "ScanFilter".  gid is
  # the site-id, assetgroup-id, or devce-id.  ScanFilter, if used, specifies
  # a specifies a specific scan to use as the data source for the report. The gid
  # can be a specific scan-id or "first" for the first run scan, or “last” for
  # the last run scan.
  class ReportFilter
    attr_reader :type
    attr_reader :id

    def initialize(type, id)
      @type = type
      @id = id
    end
  end

  # === Description
  # Object that represents the schedule on which to automatically generate new reports.
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

  # TODO: Class duplicates functionality of report_template_listing call.
  #       Should be removed if it doesn't add additional value.
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

  # TODO Same functionality in report_listing method.
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

  # TODO: Is this class useful? Summaries produced by report_template_listing.
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
