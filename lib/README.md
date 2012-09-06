# Nexpose Client

The nexpose.rb file should act simply as a means of collecing all the sub-elements of the client into a single module.

If adding or adjusting code, please note that all calls directly against the Connection object are currently implemented within the NexposeAPI module. This style of call should mostly be for listing and simple query calls, and not for configuration requests that will return an editable class.
