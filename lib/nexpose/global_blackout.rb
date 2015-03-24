module Nexpose

  class Global_Blackout < APIObject
    include JsonSerializer

    # [Array] Blackout starting dates, times and duration for blackout periods.
    attr_accessor :blackout

    def initialize(blackout)
      @global_blackout = Array(blackout)
    end

    def save(nsc)
      params = to_json
      JSON.parse(AJAX.post(nsc, '/api/2.1/silo_blackout/', params, AJAX::CONTENT_TYPE::JSON))
    end

    def to_h
      {
          blackouts:
              (@global_blackout || []).map { |blackout| blackout.to_h }
      }
    end

    def to_json
      JSON.generate(to_h)
    end

    def self.json_initializer(data)
      new(blackout: data)
    end

    require 'json'

    def self.load(nsc)
      uri = '/api/2.1/silo_blackout/'
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      # puts resp
      hash = JSON.parse(resp, symbolize_names: true)
      blackout = self.json_initializer(hash).deserialize(hash)
      blackout.blackout = (hash[:blackouts] || []).map { |blackout| Nexpose::Blackout.from_hash(blackout) }
      blackout
    end
  end
end



