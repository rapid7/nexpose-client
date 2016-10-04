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
  describe '#include?' do
    context 'testing inclusion from a single ip' do
      subject { Nexpose::IPRange.new('192.168.1.1') }
      context 'with an IPAddr argument' do
        it 'returns false if the other ip is not equal' do
          other = IPAddr.new('192.168.1.2')
          expect(subject.include?(other)).to be_falsey
        end
        it 'returns true if the other ip is equal' do
          other = IPAddr.new('192.168.1.1')
          expect(subject.include?(other)).to be_truthy
        end
      end
      context 'with an IPRange argument' do
        it 'returns false if the other.size > 1' do
          other = Nexpose::IPRange.new('192.168.1.1','192.168.1.2')
          expect(subject.include?(other)).to be_falsey
        end
        it 'returns false if the other.size==1 and other.from!=self.from' do
          other = Nexpose::IPRange.new('192.168.1.2')
          expect(subject.include?(other)).to be_falsey
        end
        it 'returns true if the other.from == self.from' do
          other = Nexpose::IPRange.new('192.168.1.1')
          expect(subject.include?(other)).to be_falsey
        end
      end
    end
    context 'testing inclusion from a spanning range' do
      subject { Nexpose::IPRange.new('192.168.1.1','192.168.1.3') }
      context 'with an IPAddr argument' do
        it 'returns true if self.from <= other <= self.to'
        it 'returns false otherwise'
        it 'raises an ArgumentError if the string cannot instantiate an IPAddr'
      end
      context 'with an IPRange argument' do
        it 'returns false if the other.size > 1'
        it 'returns true if the other self.from == self.from'
      end
    end
    context 'called with a castable other' do
      subject { Nexpose::IPRange.new('192.168.1.1','192.168.1.3') }
      it 'casts other to IPAddr'
      it 'raises an ArgumentError for unusable arguments'
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
