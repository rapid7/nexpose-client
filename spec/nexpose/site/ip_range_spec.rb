require 'spec_helper'

describe Nexpose::IPRange do
  describe '#<=>' do
    context 'with two from IP addresses' do
      it 'returns -1 when the first from address is less than the second' do
        first = Nexpose::IPRange.new('192.168.1.0')
        second = Nexpose::IPRange.new('192.168.1.1')
        expect(first).to be < second
      end
    end

    context 'with two from IP address and one to IP address' do
      it 'returns 0 when the first from address is equal to the second' do
        first = Nexpose::IPRange.new('192.168.1.0')
        second = Nexpose::IPRange.new('192.168.1.0')

        # TODO: IPRange#== is currently overridden instead of being defined by
        # IPRange#<=>
        expect(first <=> second).to be_zero
      end
    end

    context 'with one from IP address' do
      it 'returns 1 when the first from address is greater than the second' do
        first = Nexpose::IPRange.new('192.168.1.1')
        second = Nexpose::IPRange.new('192.168.1.0')
        expect(first).to be > second
      end
    end
  end

  describe '#as_xml' do
    include Helpers::XML

    context 'with a single IP address' do
      subject { Nexpose::IPRange.new('192.168.1.0').as_xml }

      it 'creates a range node with from and to parameters' do
        expect(subject).to have_name('range')

        attributes = attributes_to_hash(subject.attributes)
        expect(attributes).to include('from' => '192.168.1.0')
        expect(attributes['to']).to be_nil
      end
    end

    context 'with multiple IP addresses' do
      subject { Nexpose::IPRange.new('192.168.1.0', '192.168.1.255').as_xml }

      it 'creates a range node with from and to parameters' do
        expect(subject).to have_name('range')

        attributes = attributes_to_hash(subject.attributes)
        expect(attributes).to include(
          'from' => '192.168.1.0',
          'to' => '192.168.1.255'
        )
      end
    end

    context 'with a CIDR notation IP range' do
      subject { Nexpose::IPRange.new('192.168.1.0/24').as_xml }

      it 'creates a range node with from and to parameters' do
        expect(subject).to have_name('range')

        attributes = attributes_to_hash(subject.attributes)
        expect(attributes).to include(
          'from' => '192.168.1.0',
          'to' => '192.168.1.255'
        )
      end
    end
  end

  describe '#include?' do
    subject { Nexpose::IPRange.new('192.168.1.0', '192.168.1.255') }

    context 'with a invalid IP string' do
      it 'returns false' do
        expect(subject).to_not include('127.0.0.1')
      end
    end

    context 'with a valid IP string' do
      it 'returns true' do
        expect(subject).to include('192.168.1.1')
      end
    end

    context 'with an invalid IPRange' do
      it 'returns false' do
        expect(subject).to_not include(Nexpose::IPRange.new('127.0.0.1'))
      end
    end

    context 'with a subset in an IPRange' do
      it 'returns true' do
        expect(subject).to include(Nexpose::IPRange.new('192.168.1.1'))
      end
    end
  end

  describe '#size' do
    context 'with a single IP address' do
      subject { Nexpose::IPRange.new('192.168.1.0') }

      it 'returns one' do
        expect(subject.size).to eq(1)
      end
    end

    context 'with multiple IP addresses' do
      subject { Nexpose::IPRange.new('192.168.1.0', '192.168.1.255') }

      it 'returns 256' do
        expect(subject.size).to eq(256)
      end
    end

    context 'with a CIDR notation IP range' do
      subject { Nexpose::IPRange.new('192.168.1.0/24') }

      it 'returns 256' do
        expect(subject.size).to eq(256)
      end
    end
  end
end
