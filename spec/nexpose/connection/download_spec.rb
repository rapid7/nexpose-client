require 'spec_helper'
require 'tempfile'

describe Nexpose::Connection, :with_api_login do
  describe '#download' do
    let(:report_url) { 'https://nexpose.local:3780/reports/00000001/00000002/report.xml' }

    it 'downloads report to string' do
      report = VCR.use_cassette('download_report') do
        connection.download(report_url)
      end

      expect(report).to eq('<NexposeReport version="2.0"></NexposeReport>')
    end

    it 'downloads report with file name' do
      tf = Tempfile.new
      path = tf.path
      tf.close
      tf.unlink

      begin
        VCR.use_cassette('download_report') do
          connection.download(report_url, path)
        end

        expect(File.read(path)).to eq('<NexposeReport version="2.0"></NexposeReport>')
      ensure
        File.delete(path) if File.exist?(path)
      end
    end

    it 'downloads report with file object' do
      tf = Tempfile.new

      begin
        VCR.use_cassette('download_report') do
          connection.download(report_url, tf)
        end

        expect(tf.read).to eq('<NexposeReport version="2.0"></NexposeReport>')
      ensure
        tf.close
        tf.unlink
      end
    end
  end
end
