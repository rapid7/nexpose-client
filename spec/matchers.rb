class MatchingSite
  def initialize(attributes)
    @attributes = attributes
  end

  def ==(other)
    attributes.all? do |attribute_name, attribute_value|
      unless other.respond_to?(attribute_name)
        fail(
          RSpec::ExpectationNotMetError,
          "Expected #{other} to respond to #{attribute_name}."
        )
      end

      attribute_value == other.public_send(attribute_name)
    end
  end

  private

  attr_reader :attributes
end

RSpec::Matchers.define :a_site_matching do |expected|
  match do |actual|
    @expected = MatchingSite.new(expected)
    @expected == actual
  end

  failure_message do |actual|
    "expected #{@expected} to match #{actual}"
  end

  failure_message_when_negated do |actual|
    "expected #{@expected} to not match #{actual}"
  end
end
