require 'eso/service'

module Eso
  class Conductor < Service

    # Constructor for Conductor.
    #
    # @param [String] host Hostname or IP address where this conductor resides.
    # @param [Integer] port The TCP port to connect to this conductor on.
    # @param [Nexpose::Connection] nsc A logged-in Nexpose::Connection object with a valid session used to authenticate.
    # @return [Eso::Conductor] The newly created conductor object
    #
    def initialize(host:, port: 3780, nsc:)
      super(host: host, port: port, nsc: nsc)
      @url = "https://#{@host}:#{@port}/eso/conductor-service/api/"
    end

    # Return all of the workflows that currently exist on this conductor.
    #
    # @return [Array] An array containing all of the current workflows on the conductor in Eso::Workflow object format. Returns an empty array if no workflows are present.
    #
    def workflows
      rv = []
      json_data = get(url: "#{@url}workflows/")
      json_data.each do |wf|
        workflow = Workflow.new(id: wf[:id], name: wf[:name])
        steps = wf[:steps]
        steps.each do |step|
          workflow_step = Step.new(uuid: step[:uuid],
                                   service_name: step[:serviceName],
                                   workflow: workflow,
                                   type_name: step[:stepConfiguration][:typeName],
                                   previous_type_name: step[:stepConfiguration][:previousTypeName],
                                   configuration_params: step[:stepConfiguration][:configurationParams])
          workflow.steps << workflow_step
        end
        rv << workflow
      end
      rv
    end

    # Return the workflow histories with only the state histories for the given date range.
    #
    # @param [Fixnum] starttime The time in milliseconds since epoch for which you want the workflow histories
    # @param [Fixnum] endtime The time in milliseconds since epoch for which you want the workflow histories
    # @return [Array[Eso::Workflow::History]] An array containing all of the workflow histories from the
    #   Conductor, which has StateHistory objects containing startTime's within the specified time range. Only the
    #   StateHistories within that range are returned in the WorkflowHistory object. Returns an empty array if none are present.
    def workflow_histories(starttime, endtime)
      histories = []
      json_data = get(url: "#{@url}workflows/history/#{starttime}/#{endtime}")
      json_data.each do |wf|
        # Initialize WorkflowHistory elements
        workflow_steps = []
        state_histories = []

        # Create a new WorkflowHistory with the details we already know
        workflow_history = Eso::Workflow::History.new(id: wf[:id],
                                                      name: wf[:name],
                                                      timeCreated: wf[:timeCreated],
                                                      state: wf[:state],
                                                      message: wf[:message],
                                                      steps: workflow_steps,
                                                      history: state_histories
        )

        # Parse the steps out of the response to be returned with the WorkflowHistory
        wf[:steps].each do |step|
          workflow_steps << Step.new(uuid: step[:uuid],
                                   service_name: step[:serviceName],
                                   workflow: workflow_history,
                                   type_name: step[:stepConfiguration][:typeName],
                                   previous_type_name: step[:stepConfiguration][:previousTypeName],
                                   configuration_params: step[:stepConfiguration][:configurationParams])
        end
        workflow_history.steps = workflow_steps

        # Parse the histories out of the response, to be returned with the WorkflowHistory. For some reason.
        # this failed with named parameters. For now I returned it to positional.
        wf[:history].each do |history|
          state_histories << Eso::Workflow::StateHistory.new(history[:message],
                                           history[:state],
                                           history[:startTime])
        end
        workflow_history.state_histories = state_histories

        # Add the Workflow History we just built to the list to be returned.
        histories << workflow_history
      end
      histories
    end

    # Get the state of the specified workflow.
    #
    # @param [String] workflow_id The ID of the workflow to retrieve the state of.
    # @return [String] The current state of the workflow.
    #
    def workflow_state(workflow_id:)
      get(url: "#{@url}workflows/#{workflow_id}/state")
    end

    # Get the count of items in a state of the specified workflow.
    #
    # @param [Eso::Workflow::State] state The state of the workflows to retrieve the count of.
    # @return [Integer] The number of workflows in the requested state.
    #
    def workflows_state_count(state)
      get(url: "#{@url}workflows/count/#{state}")
    end

    # Retrieve the states for all of the workflows created on the conductor.
    #
    # @return [Hash] A hash containing the states of all existing workflows, keyed by workflow ID.
    #
    def workflow_states
      wfs = workflows
      states = {}
      wfs.each { |wf| states[wf.id] = workflow_state(workflow_id: wf.id) }
      states
    end

    # Create a new workflow on this conductor.
    #
    # @param [String] name The user-facing name the workflow will be created with.
    # @param [Array] steps An array containing each of the steps that the workflow will be created with, in Eso::Step format.
    # @return [Eso::Workflow] The newly created workflow object
    #
    def create_workflow(name:, steps:)
      workflow = Workflow.new(name: name, steps: steps)

      resp = post(url: "#{@url}workflows/", payload: workflow.to_json)
      created_workflow = Workflow.load(self, resp[:id])

      created_workflow
    end

    # Update an existing workflow on the conductor to have the configuration of the workflow object passed into this method.
    #
    # @param [Eso::Workflow] updated_workflow A workflow object that has already had all required changes made to it. This workflow must have an ID set.
    #
    def update_workflow(updated_workflow:)
      payload = updated_workflow.to_json
      put(url: "#{@url}workflows/#{updated_workflow.id}", payload: payload)
    end

    # Delete an existing workflow from the conductor.
    #
    # @param [String] workflow_id The ID of the workflow to be deleted.
    #
    def delete_workflow(workflow_id:)
      delete(url: "#{@url}workflows/#{workflow_id}")
    end

    # Delete all current workflows on the conductor.
    #
    def delete_all_workflows
      wfs = workflows
      wfs.each { |wf| delete_workflow(workflow_id: wf.id) }
    end

    # Start the specified workflow.
    #
    # @param [String] workflow_id The ID of the workflow to be started.
    #
    def start_workflow(workflow_id:)
      post(url: "#{@url}workflows/#{workflow_id}/state")
    end

    # Stop the specified workflow.
    #
    # @param [String] workflow_id The ID of the workflow to be stopped.
    #
    def stop_workflow(workflow_id:)
      delete(url: "#{@url}workflows/#{workflow_id}/state")
    end

    # Start all workflows that exist on the conductor.
    #
    # @return [Hash] A hash containing the states of all existing workflows, keyed by workflow ID.
    #
    def start_all_workflows
      wf_states = workflow_states

      wf_states.each { |wf_id, state| start_workflow(workflow_id: wf_id) if state[:workflow_state] == "STOPPED" }
      workflow_states
    end

    # Stop all workflows that exist on the conductor.
    #
    # @return [Hash] A hash containing the states of all existing workflows, keyed by workflow ID.
    #
    def stop_all_workflows
      wf_states = workflow_states

      wf_states.each { |wf_id, state| stop_workflow(workflow_id: wf_id) if state[:workflow_state] == "RUNNING" }
      workflow_states
    end

    # Returns the translated value of the specified key for a step type (defined in Eso::StepNames).
    # The translated value will be based on the language settings the user has configured.
    #
    # @param [String] step_type The step type to query metadata for. Valid values defined in Eso::StepNames
    # @param [String] key The key value in the metadata that maps to the desired label.
    # @return [String] The translated value of the key.
    #
    def get_translation_label(step_type, key)
      json_data = get(url: "#{@url}services/nexpose/metadata/#{step_type}")

      target_hash = json_data[:labels].values.find { |label_hash| label_hash.has_key?(key) }
      target_hash[key] if target_hash
    end

    # Returns the metadata key for a specified translated string.
    # The translated value needs to be in language that the user has configured.
    #
    # @param [String] step_type The step type to query metadata for. Valid values defined in Eso::StepNames
    # @param [String] label The translated value of which you are requesting the key for.
    # @return [String] The metadata key corresponding to this label.
    #
    def get_translation_key(step_type, label)
      json_data = get(url: "#{@url}services/nexpose/metadata/#{step_type}")

      target_hash = json_data[:labels].values.find { |label_hash| label_hash.values.include?(label) }
      target_hash.key(label).to_s if target_hash
    end
  end
end
