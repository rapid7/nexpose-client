module Nexpose
  require 'json'
  # Configuration structure for password policies.
  class PasswordPolicy < APIObject

    attr_accessor :policyName
    attr_accessor :minLength
    attr_accessor :maxLength
    attr_accessor :capitals
    attr_accessor :digits
    attr_accessor :specialChars

    def initialize(policyName:, minLength:, maxLength:, specialChars:, capitals:, digits:)
      @policyName = policyName.to_s
      @minLength = minLength.to_i
      @maxLength = maxLength.to_i
      @specialChars = specialChars.to_i
      @capitals = capitals.to_i
      @digits = digits.to_i
    end

    def self.from_hash(hash)
      new(hash[:policyName],
          hash[:minLength],
          hash[:maxLength],
          hash[:specialChars],
          hash[:capitals],
          hash[:digits])
    end

    def to_h
      {
          policyName: @policyName,
          minLength: @minLength,
          maxLength: @maxLength,
          specialChars: @specialChars,
          capitals: @capitals,
          digits: @digits
      }
    end

    def to_json
      JSON.generate(to_h)
    end

    def save(nsc)
      params = to_json
      AJAX.post(nsc, '/api/2.1/password_policy/', params, AJAX::CONTENT_TYPE::JSON)
    end

    def self.load(nsc)
      uri = '/api/2.1/password_policy/'
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      hash = JSON.parse(resp, symbolize_names: true)
      self.from_hash(hash)
    end
  end
end