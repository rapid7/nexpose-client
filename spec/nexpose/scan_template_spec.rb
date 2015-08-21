require 'spec_helper'

describe Nexpose::ScanTemplate do
  let(:template) { Nexpose::ScanTemplate.new(SecureRandom.hex(16)) }

  describe '#vuln_checks' do
    context 'by default' do
      it 'returns no enabled vuln categories' do
        expect(template.checks_by_category).to be_empty
      end
      it 'returns no enabled vuln types' do
        expect(template.checks_by_type).to be_empty
      end
      it 'returns no enabled vuln checks' do
        expect(template.vuln_checks).to be_empty
      end
    end
  end
end
