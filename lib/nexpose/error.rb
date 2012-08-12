module Nexpose
  class APIError < ::RuntimeError
    attr_accessor :req, :reason

    def initialize(req, reason = '')
      @req = req
      @reason = reason
    end

    def to_s
      "NexposeAPI: #{@reason}"
    end
  end

  class AuthenticationFailed < APIError
    def initialize(req)
      @req = req
      @reason = "Login Failed"
    end
  end
end
