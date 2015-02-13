require 'spec_helper'

describe Nexpose::IPRange do
  describe '#<=>' do
    it 'returns true for IPRanges created with two IPs and CIDR' do
      multiple_ip_range = Nexpose::IPRange.new('192.168.1.0', '192.168.1.255')
      cidr_range = Nexpose::IPRange.new('192.168.1.0/24')
      expect(cidr_range).to eq(multiple_ip_range)
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
        expect(attributes).to include('from' => '192.168.1.0', 'to' => '192.168.1.255')
      end
    end

    context 'with a CIDR notation IP range' do
      subject { Nexpose::IPRange.new('192.168.1.0/24').as_xml }

      it 'creates a range node with from and to parameters' do
        expect(subject).to have_name('range')

        attributes = attributes_to_hash(subject.attributes)
        expect(attributes).to include('from' => '192.168.1.0', 'to' => '192.168.1.255')
      end
    end
  end
end
