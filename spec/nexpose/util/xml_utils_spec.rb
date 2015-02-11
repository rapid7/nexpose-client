require 'spec_helper'

describe Nexpose::XMLUtils do
  describe '.success?' do
    subject { Nexpose::XMLUtils }

    context 'with a successful response' do
      let(:response_string) { '<status success="1"/>' }

      it 'returns true' do
        observed = subject.success?(response_string)
        expect(observed).to be(true)
      end
    end

    context 'with a failed response' do
      let(:response_string) { '<status success="0"/>' }

      it 'returns false' do
        observed = subject.success?(response_string)
        expect(observed).to be(false)
      end
    end

    context 'with a response that did not define "success"' do
      let(:response_string) { '<status other-attr="ignored"/>' }

      it 'returns false' do
        observed = subject.success?(response_string)
        expect(observed).to be(false)
      end
    end
  end
end
