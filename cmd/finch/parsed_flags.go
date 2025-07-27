package main

// parsedFlags groups additional command line options passed to the runtime.
type parsedFlags struct {
	ConfigPath   string
	LogLevel     string
	SSEAddr      string
	SSEEnabled   bool
	AdminEnabled bool
	AdminAddr    string
	AdminToken   string
	EchoMode     bool
}
