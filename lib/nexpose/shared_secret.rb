module Nexpose

  class SharedSecret
    attr_accessor :key_string
    attr_accessor :ttl

    def initialize(console, time_to_live)
      uri = "/data/admin/global/shared-secret?time-to-live=#{time_to_live}"
      json = AJAX.put(console, uri)
      from_json(json)
    end

    def self.from_json(json)
      new.tap do |shared_secret|
        shared_secret.key_string = json['keyString']
        shared_secret.ttl = json['timeToLiveInSeconds']
      end
    end

    def delete(console)
      uri = "/data/admin/global/remove-shared-secret?key-string=#{key_string}"
      json = AJAX.delete(console, uri)
    end

    def ==(other)
      return false unless self.class == other.class
      return false unless key_string.upcase == other.key_string.upcase

      true
    end
    alias_method :eql?, :==

  end
end
