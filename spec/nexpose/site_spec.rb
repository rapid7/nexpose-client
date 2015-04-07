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
      it 'adds a new IPRange to the assets list' do
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
      it 'adds a new IPRange to the assets list' do
        subject.add_asset('192.168.1.0/24')

        expect(subject.assets).to include(Nexpose::IPRange.new('192.168.1.0', '192.168.1.255'))
      end
    end
  end

  describe '#remove_asset' do
    context 'with multiple IP addresses and ranges' do
      before do
        subject.add_ip_range('192.168.0.100', '192.168.0.105')
        subject.add_ip_range('172.16.0.1', '172.16.0.3')
        subject.add_asset('172.16.0.5')
        subject.add_asset('example.local')
      end

      it 'deletes a hostname' do
        subject.remove_asset('example.local')
        expect(subject).to_not include_asset('example.local')
      end

      it 'deletes a lone IP' do
        subject.remove_asset('172.16.0.5')
        expect(subject).to_not include_asset('172.16.0.5')
      end

      it 'deletes an IP embedded in a range' do
        subject.remove_asset('172.16.0.1')
        expect(subject).to_not include_asset('172.16.0.1')
      end

      it 'splits a range after deleting an IP' do
        subject.remove_asset('192.168.0.100')
        expect(subject).to_not include_asset('192.168.0.100')
      end
    end
  end
end
