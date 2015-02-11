require 'spec_helper'

describe Nexpose::Attributes do
  subject { Nexpose::Attributes }

  describe '.to_hash' do
    it 'converts an array into a XML compatible format' do
      attributes = [
        { awesome: true },
        { boring: false }
      ]
      observed = subject.to_hash(attributes)

      expect(observed).to include(a_hash_including('key' => 'awesome', 'value' => 'true'))
        .and include(a_hash_including('key' => 'boring', 'value' => 'false'))
    end
  end
end
