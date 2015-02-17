module Nexpose

  class Wait
    ## Nexpose Universal Wait module.
    attr_reader :error_message, :ready, :retry_count

    # Setup Default error_message, set ready state to false, and allow caller to specify a retry count if there are Timeout failures.
    def initialize(retry_count: nil)
      @error_message = "Default General Failure in Nexpose::Wait"
      @ready = false
      @retry_count = retry_count.nil? ? 0 : retry_count
    end

    # Allow class to respond in a readable way to see if we are done waiting.
    def is_ready?
      @ready
    end


    # Note: Uses keyword arguments.
    # Default Timeout is 120 seconds.
    # Default Polling Interval is 1 second.
    def for_report(nsc: nil, report_id: nil, timeout: nil, polling_interval: nil)
      begin
        poller = Nexpose::Poller.new(timeout: timeout, polling_interval: polling_interval)
        poller.wait(get_report_status(nsc: nsc, report_id: report_id))
        @ready = true
      rescue TimeoutError
        retry if timeout_retry?
        @error_message = "Timeout Waiting for Report to Generate - Report Config ID: #{report_id}"
      end
    end


    def for_integration(nsc: nil, scan_id: nil, status: 'finished', timeout: nil, polling_interval: nil)
      begin
        poller = Nexpose::Poller.new(timeout: timeout, polling_interval: polling_interval)
        poller.wait(get_integration_status(nsc: nsc, scan_id: scan_id, status: status))
        @ready = true
      rescue TimeoutError
        retry if timeout_retry?
        @error_message = "Timeout Waiting for Integration Status of '#{status}' - Scan ID: #{scan_id}"
      end
    end



    private

      # Method which contains a proc that we want to evaluate to true.
      def get_report_status(nsc: nil, report_id: nil)
        Proc.new { nsc.last_report(report_id).status == 'Generated' }
      end


      def get_integration_status(nsc: nil, scan_id: scan_id, status: status)
        Proc.new { nsc.scan_status(scan_id).downcase == status.downcase }
      end

      def timeout_retry?
        if @retry_count > 0
          @retry_count = @retry_count - 1
          return true
        else
          return false
        end
      end


  end





  class Poller
    ## Stand alone object to handle waiting logic.
    attr_reader :timeout, :polling_interval, :poll_begin


    def initialize(timeout: nil, polling_interval: nil)
      global_timeout = set_global_timeout
      @timeout = timeout.nil? ? global_timeout : timeout

      global_polling = set_polling_interval
      @polling_interval = polling_interval.nil? ? global_polling : polling_interval
    end


    def wait(cond)
      @poll_begin = Time.now
      loop do
        break if cond.call
        raise TimeoutError if @poll_begin + @timeout < Time.now
        sleep @polling_interval
      end
    end




    private

      def set_global_timeout
        default_timeout = 120
        ENV['GLOBAL_TIMEOUT'].nil? ? default_timeout : ENV['GLOBAL_TIMEOUT']
      end


      def set_polling_interval
        default_polling = 1
        ENV['GLOBAL_POLLING_INTERVAL'].nil? ? default_polling : ENV['GLOBAL_POLLING_INTERVAL']
      end

  end


end
