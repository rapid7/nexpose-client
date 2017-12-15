module Eso

  # The following classes have mixed casing (snake and camel) to accommodate for the API.
  # I guess a TODO would be to write a helper to automatically convert them.
  class Workflow
    # The id of the workflow. This will be created upon saving to the server upon creation.
    attr_accessor :id

    # The name of the workflow. This is required.
    attr_accessor :name

    # An array of the steps this workflow takes action on.
    attr_accessor :steps

    # The time the workflow was created in milliseconds since epoch
    attr_accessor :timeCreated

    # Constructor for the workflow
    #
    # @param [String] id ID of the workflow.
    # @param [String] name Name of the workflow.
    # @param [Array] steps Array of the steps that this workflow takes.
    # @param [Fixnum] time_created The time the workflow was created in millis since epoch
    #
    def initialize(id: nil, name:, steps: [], time_created: (Time.now.strftime('%s').to_i * 1000))
      @id = id
      @name = name
      @steps = steps
      @timeCreated = time_created
    end

    # Load an existing workflow from the API.
    #
    # @param [Conductor] conductor The Conductor object governing the workflows
    # @param [String] id ID of the workflow to load
    # @return [Workflow] Workflow object that was loaded.
    #
    def self.load(conductor, id)
      uri = "#{conductor.url}workflows/#{id}"
      resp = conductor.get(url: uri)
      workflow = self.new(id: resp[:id], name: resp[:name])
      steps = resp[:steps]
      steps.each do |step|
        workflow_step = Step.new(uuid: step[:uuid],
                                 service_name: step[:serviceName],
                                 workflow: workflow,
                                 type_name: step[:stepConfiguration][:typeName],
                                 previous_type_name: step[:stepConfiguration][:previousTypeName],
                                 configuration_params: step[:stepConfiguration][:configurationParams])
        workflow.steps << workflow_step
      end
      workflow
    end

    # Return the relevant step based on the given service name.
    # For example, if you want the step related to the scan service you would pass 'nexpose-scan-service'.
    #
    # @param [String] service_name Service name to be returned.
    # @return [Step] Step object corresponding to the given service.
    #
    def get_step(type_name)
      @steps.find do |step|
        step.type_name == type_name
      end
    end

    # Return the trigger step of a workflow. The trigger step is defined as a step that monitors for events
    # that will cause the action to fire.
    #
    # Currently triggers do not have a previous-action so that is what this is returning. This behavior could change in ESO's future.
    #
    # @return [Step] Step object representation of the trigger step.
    #
    def trigger
      @steps.find do |step|
        step.stepConfiguration.previousTypeName.nil?
      end
    end

    # Return this object and the associated steps in a digestible JSON format.
    #
    # @return [String] JSON interpretation of this workflow.
    #
    def to_json
      hash = self.to_hash
      steps = hash['steps']
      hashified_steps = []
      steps.each { |step| hashified_steps << step.to_hash }
      hash['steps'] = hashified_steps
      hash.to_json
    end

    # Return this object as a hash.
    # The corresponding steps will still be objects.
    #
    # @return [Hash{}] Hash interpretation of this workflow.
    def to_hash
      hash = {}
      instance_variables.each { |var| hash[var.to_s.delete('@')] = instance_variable_get(var) }
      hash
    end

    # Representation of state of a workflow or integration option. Taken from service-orchestration State.java
    module State
      # Workflow or an integration option is configured and ready to accept events
      READY = 'ready'

      # Workflow or an integration option is processing or has processed events
      RUNNING = 'running'

      # The workflow or an integration option is running, but is temporarily unsuccessful processing events
      RETRY = 'retry'

      # Workflow or an integration option is stopped by the user
      STOPPED = 'stopped'

      # Workflow or an integration option has experienced an error that caused it to stop
      ERROR = 'error'
    end

    StateHistory = Struct.new(:message, :state, :startTime)

    class History < Workflow
      # The current state of the workflow
      attr_accessor :state

      # The most recent message
      attr_accessor :message

      # An array of Eso::Workflow::StateHistory
      attr_accessor :state_histories

      # Constructor for the WorkflowHistory
      #
      # @param [String] id ID of the workflow.
      # @param [String] name Name of the workflow.
      # @param [Array] steps Array of the steps that this workflow takes.
      # @param [Fixnum] time_created The time the workflow was created in millis since epoch
      # @param [Eso::Workflow::State] state The current state of the workflow
      # @param [String] message The most recent message
      def initialize(id:, name:, time_created:, steps:, state:, message:, history:)
        super(id: id, name: name, timeCreated: time_created, steps: steps)
        @state = state
        @message = message
        @state_histories = history
      end
    end
  end
end
