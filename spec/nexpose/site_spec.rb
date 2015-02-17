require 'spec_helper'

describe Nexpose::Site do
  let(:scan_template) { 'full-audit-without-webspider' }
  let(:site_name) { 'joe blow site' }
  subject { Nexpose::Site.new(site_name, scan_template) }

  describe '#add_asset' do
    context 'with a hostname' do
      it 'adds a new HostName to the assets list' do
        subject.add_asset('nexpose.local')

        expect(subject.assets).to include(Nexpose::HostName.new('nexpose.local'))
      end
    end

    context 'with a single IP address' do
      it 'adds a new IPRange to the assets list' do
        subject.add_asset('192.168.1.1')

        expect(subject.assets).to include(Nexpose::IPRange.new('192.168.1.1'))
      end
    end

    context 'with a multiple IP address' do
      # TODO: The IPRange class apparently doesn't handle CIDR notation on the client side
      xit 'adds a new IPRange to the assets list' do
        subject.add_asset('192.168.1.0/24')

        expect(subject.assets).to include(Nexpose::IPRange.new('192.168.1.0', '192.168.1.255'))
      end
    end
  end

  describe '#add_host' do
    it 'adds a new HostName to the assets list' do
      subject.add_asset('nexpose.local')

      expect(subject.assets).to include(Nexpose::HostName.new('nexpose.local'))
    end
  end

  describe '#add_ip' do
    context 'with a single IP address' do
      it 'adds a new IPRange to the assets list' do
        subject.add_asset('192.168.1.1')

        expect(subject.assets).to include(Nexpose::IPRange.new('192.168.1.1'))
      end
    end

    context 'with a multiple IP address' do
      # TODO: The IPRange class apparently doesn't handle CIDR notation on the client side
      xit 'adds a new IPRange to the assets list' do
        subject.add_asset('192.168.1.0/24')

        expect(subject.assets).to include(Nexpose::IPRange.new('192.168.1.0', '192.168.1.255'))
      end
    end
  end
end
