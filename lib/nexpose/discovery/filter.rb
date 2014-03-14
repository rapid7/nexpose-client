module Nexpose
  module Search
    module Field

      # Valid Operators: IS, IS_NOT, CONTAINS, NOT_CONTAINS, STARTS_WITH
      CLUSTER = 'CLUSTER'

      # Valid Operators: IS, IS_NOT
      DATACENTER ='DATACENTER'

      # Valid Operators: CONTAINS, NOT_CONTAINS
      GUEST_OS_FAMILY = 'GUEST_OS_FAMILY'

      # Valid Operators: IN, NOT_IN
      IP_ADDRESS_RANGE = 'IP_ADDRESS'

      # Valid Operators: IN, NOT_IN
      # Valid Values (See Value::PowerState): ON, OFF, SUSPENDED
      POWER_STATE = 'POWER_STATE'

      # Valid Operators: CONTAINS, NOT_CONTAINS
      RESOURCE_POOL_PATH ='RESOURCE_POOL_PATH'

      # Valid Operators: IS, IS_NOT, CONTAINS, NOT_CONTAINS, STARTS_WITH
      VIRTUAL_MACHINE_NAME = 'VM'
    end

    module Value
      module PowerState
        ON = 'poweredOn'
        OFF = 'poweredOff'
        SUSPENDED = 'suspended'
      end
    end
  end
end
