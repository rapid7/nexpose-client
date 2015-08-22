require 'spec_helper'
require 'securerandom'

describe Nexpose::ScanTemplate do
  let(:random_things) { 0.upto(1+rand(10)).to_a.map { |t| SecureRandom.hex(8) } }
  subject { described_class.new(IO.read(File.join(%w(spec data example_template.xml)))) }

  context 'vulnerability checks' do
    context 'by default' do
      it 'returns no enabled vulnerability checks' do
        expect(subject.vuln_checks).to be_empty
      end
    end
    context 'when checks are enabled' do
      it 'returns enabled vulnerability checks' do
        random_things.each do |thing|
          subject.enable_vuln_check(thing)
        end
        expect(subject.vuln_checks).to eq(random_things)
      end
    end
    context 'when checks are disabled' do
      skip 'returns disabled vulnerability checks' do
        random_things.each do |thing|
          subject.disable_vuln_check(thing)
        end
        expect(subject.vuln_checks).to eq(random_things)
      end
    end
  end

  context 'vulnerability categories' do
    context 'by default' do
      it 'returns no enabled vulnerability categories' do
        expect(subject.checks_by_category).to be_empty
      end
    end
    context 'when categories are enabled' do
      it 'returns enabled vulnerability categories' do
        random_things.each do |thing|
          subject.enable_checks_by_category(thing)
        end
        expect(subject.checks_by_category).to eq(random_things)
      end
    end
    context 'when categories are disabled' do
      skip 'returns disabled vulnerability categories' do
        random_things.each do |thing|
          subject.disable_checks_by_category(thing)
        end
        expect(subject.checks_by_category).to eq(random_things)
      end
    end
  end

  context 'vulnerability types' do
    context 'by default' do
      it 'returns no enabled vulnerability types' do
        expect(subject.checks_by_type).to be_empty
      end
    end
    context 'when types are enabled' do
      it 'returns enabled vulnerability types' do
        random_things.each do |thing|
          subject.enable_checks_by_type(thing)
        end
        expect(subject.checks_by_type).to eq(random_things)
      end
    end
    context 'when types are disabled' do
      skip 'returns disabled vulnerability types' do
        random_things.each do |thing|
          subject.disable_checks_by_type(thing)
        end
        expect(subject.checks_by_type).to eq(random_things)
      end
    end
  end
end
