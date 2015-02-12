require 'spec_helper'

describe Nexpose::Sanitize do
  subject do
    # Create a dummy class which has included the Sanitize module
    dummy_class = Class.new { include Nexpose::Sanitize }
    dummy_class.new
  end

  describe '#replace_entities' do
    it 'replaces all instances of the ampersand character with &amp;' do
      observed = subject.replace_entities('one & two & three')
      expect(observed).to eq('one &amp; two &amp; three')
    end

    it 'replaces all instances of the double quote character with &quot;' do
      observed = subject.replace_entities('Lorem "ipsum"')
      expect(observed).to eq('Lorem &quot;ipsum&quot;')
    end

    it 'replaces all instances of the single quote character with &apos;' do
      observed = subject.replace_entities("Lorem 'ipsum'")
      expect(observed).to eq('Lorem &apos;ipsum&apos;')
    end

    it 'replaces all instances of the "greater than" character' do
      observed = subject.replace_entities("n_bits >> m_bits")
      expect(observed).to eq('n_bits &gt;&gt; m_bits')
    end

    it 'replaces all instances of the "less than" character' do
      observed = subject.replace_entities("array << Time.now")
      expect(observed).to eq('array &lt;&lt; Time.now')
    end
  end
end
