module Nexpose
  # Object that represents a single IP address or an inclusive range of IP addresses.
  # If to is nil then the from field will be used to specify a single IP Address only.
  #
  class IPRange
    # Start of range *Required
    attr_accessor :from
    # End of range *Optional (If nil then IPRange is a single IP Address)
    attr_accessor :to

    # @overload initialize(ip)
    #   @param [#to_s] from the IP single IP address.
    #   @example
    #     Nexpose::IPRange.new('192.168.1.0')
    #
    # @overload initialize(start_ip, end_ip)
    #   @param [#to_s] from the IP to start the range with.
    #   @param [#to_s] to the IP to end the range with.
    #   @example
    #     Nexpose::IPRange.new('192.168.1.0', '192.168.1.255')
    #
    # @overload initialize(cidr_range)
    #   @param [#to_s] from the CIDR notation IP address range.
    #   @example
    #     Nexpose::IPRange.new('192.168.1.0/24')
    #   @note The range will not be stripped of reserved IP addresses (such as
    #     x.x.x.0 and x.x.x.255).
    #
    # @return [IPRange] an IP address range of one or more addresses.
    def initialize(lower, upper = nil)
      range = IPAddr.new(lower).to_range
      span = range.last.to_i - range.first.to_i
      @to = case upper
            when nil, lower
              span > 0 ? range.last.to_s : nil
            else
              IPAddr.new(upper).to_s
            end
      @from = range.first.to_s
    end

    # Size of the IP range. The total number of IP addresses represented
    # by this range.
    #
    # @return [Fixnum] size of the range.
    #
    def size
      1 + case @to
          when nil
            0
          else
            upper_ip.to_i - lower_ip.to_i
          end
    end

    def single?
      (size == 1)
    end

    include Comparable

    def <=>(other)
      case other
      when Nexpose::IPRange
        if other.upper_ip < lower_ip
          1
        elsif upper_ip < other.lower_ip
          -1
        else # Overlapping
          0
        end
      else
        (addr = coerce_address(other)) ? self.<=>(Nexpose::IPRange.new(addr)) : 1
      end
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      return false unless other.respond_to? :from
      @from == other.from && @to == other.to
    end

    #
    # @overload include?(other)
    #   @param other [IPAddr] /32 IP address
    #
    # @overload include?(IPAddr)
    #   @param other [IPAddr] CIDR range
    #
    # @overload include?(other)
    #   @param other [IPRange] single IP address
    #
    # @overload include?(other)
    #   @param other [IPRange] IPRange spanning multiple IPs
    #
    # @overload include?(other)
    #   @param other [String] /32 IP address
    #
    # @overload include?(other)
    #   @param other [String] CIDR range
    #
    # @return [FalseClass]|[TrueClass] if other is bounded inclusively by #from and #to
    #
    def include?(other)
      case other
      when IPAddr
        include_ipaddr?(other)
      when Nexpose::IPRange
        include_iprange?(other)
      when String
        other_addr = coerce_address(other)
        other_addr ? include_ipaddr?(other_addr) : false
      else
        raise ArgumentError, "incompatible type: #{other.class} cannot be coerced to IPAddr or Nexpose::IPRange"
      end
    end

    def hash
      to_xml.hash
    end

    def as_xml
      xml = REXML::Element.new('range')
      xml.add_attributes('from' => @from, 'to' => @to)
      xml
    end
    alias_method :to_xml_elem, :as_xml

    def to_xml
      as_xml.to_s
    end

    def to_s
      return from.to_s if to.nil?
      "#{from} - #{to}"
    end

    def lower_ip
      IPAddr.new(@from)
    end

    def upper_ip
      @to.nil? ? IPAddr.new(@from) : IPAddr.new(@to)
    end

    private

    def coerce_address(str)
      addr = begin
        IPAddr.new(str)
      rescue IPAddr::AddressFamilyError, IPAddr::InvalidAddressError => invalid
        warn format('could not coerce "%s" to IPAddr: %s', str, invalid.to_s)
        false
      end
      addr
    end

    def include_ipaddr?(other)
      ip_range = other.to_range
      lower = ip_range.first.to_s
      upper = ip_range.last.to_s
      nxp_iprange = Nexpose::IPRange.new(lower, upper)
      include_iprange?(nxp_iprange)
    end

    def include_iprange?(other)
      if single?
        other.single? ? eql?(other) : false
      else
        (lower_ip <= other.lower_ip) && (other.upper_ip <= upper_ip)
      end
    end
  end
end
