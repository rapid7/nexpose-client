require 'spec_helper'

describe Nexpose::HostOrIP do
  subject { Nexpose::HostOrIP }

  describe '.convert' do
    context 'with a fully qualified domain name' do
      let(:asset) { 'nexpose.local' }

      it 'returns a HostName' do
        observed = subject.convert(asset)
        expect(observed).to be_a(Nexpose::HostName)
      end
    end

    context 'with a hostname' do
      let(:asset) { 'target-host' }

      it 'returns a HostName' do
        observed = subject.convert(asset)
        expect(observed).to be_a(Nexpose::HostName)
      end
    end

    context 'with an IP address' do
      let(:asset) { '192.168.1.1' }

      it 'returns an IPRange' do
        observed = subject.convert(asset)
        expect(observed).to be_a(Nexpose::IPRange)
      end
    end

    context 'with an IP address range in CIDR format' do
      let(:asset) { '192.168.1.0/24' }

      it 'returns an IPRange' do
        observed = subject.convert(asset)
        expect(observed).to be_a(Nexpose::IPRange)
      end
    end

    context 'with an IP address range without whitespace' do
      let(:asset) { '192.168.1.0-192.168.1.255' }

      it 'returns an IPRange' do
        observed = subject.convert(asset)
        expect(observed).to be_a(Nexpose::IPRange)
      end
    end

    context 'with an IP address range with whitespace' do
      let(:asset) { '192.168.1.0   -   192.168.1.255' }

      it 'returns an IPRange' do
        observed = subject.convert(asset)
        expect(observed).to be_a(Nexpose::IPRange)
      end
    end
  end

  # TODO: Since HostOrIP.parse deals with API responses consider adding
  #   integration tests for the parse method.
  describe '.parse' do
    let(:multiple_address_range_xml) { '<range from="192.168.1.1" to="192.168.1.254"/>' }
    let(:single_address_range_xml) { '<range from="192.168.2.1"/>' }
    let(:host_xml) { '<host>nexpose.local</host>' }
    let(:xml_format) { '<GlobalSettings><ExcludedHosts>%{nested_xml}</ExcludedHosts></GlobalSettings>' }

    context 'with a host element' do
      let(:xml) { REXML::Document.new(format(xml_format, nested_xml: host_xml)) }

      it 'returns a valid HostName object' do
        observed = subject.parse(xml)
        expect(observed).to include(Nexpose::HostName.new('nexpose.local'))
      end
    end

    context 'with a single IP range element' do
      let(:xml) { REXML::Document.new(format(xml_format, nested_xml: single_address_range_xml)) }

      it 'returns a valid IPRange object' do
        observed = subject.parse(xml)
        expect(observed).to include(Nexpose::IPRange.new('192.168.2.1'))
      end
    end

    context 'with a multiple IP range element' do
      let(:xml) { REXML::Document.new(format(xml_format, nested_xml: multiple_address_range_xml)) }

      it 'returns a valid IPRange object' do
        observed = subject.parse(xml)
        expect(observed).to include(Nexpose::IPRange.new('192.168.1.1', '192.168.1.254'))
      end
    end

    context 'with host, IP address, and range elements' do
      let(:xml) do
        nodes = [host_xml, single_address_range_xml, multiple_address_range_xml]
        REXML::Document.new(format(xml_format, nested_xml: nodes.join))
      end

      it 'returns valid HostName and IPRange objects' do
        observed = subject.parse(xml)
        expect(observed).to include(
          Nexpose::IPRange.new('192.168.2.1'),
          Nexpose::HostName.new('nexpose.local'),
          Nexpose::IPRange.new('192.168.1.1', '192.168.1.254')
        )
      end
    end
  end
end
