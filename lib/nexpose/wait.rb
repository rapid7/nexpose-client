module Nexpose

  class Wait
    ## Nexpose Universal Wait module.
    attr_reader :error_message, :ready

    # Setup Default error_message, and set ready state to false.
    def initialize
      @error_message = "Default General Failure in Nexpose::Wait"
      @ready = false
    end

    # Allow class to respond in a readable way to see if we are done waiting.
    def is_ready?
      @ready
    end


    # Note: Uses keyword arguments.
    def for_report(nsc:, report_id:, timeout: nil, polling_interval: nil)
      begin
        poller = Nexpose::Poller.new(timeout: timeout, polling_interval: polling_interval)
        poller.wait(get_report_status(nsc: nsc, report_id: report_id))
        @ready = true
      rescue TimeoutError
        @error_message = "Timeout Waiting for Report to Generate - Report Config ID: #{report_id}"
      end
    end





    private

      def get_report_status(nsc:, report_id:)
        Proc.new { nsc.last_report(report_id).status == 'Generated' }
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
