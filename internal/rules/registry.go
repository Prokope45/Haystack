package rules

// DefaultRegistry creates and populates a Rule Registry with all default rules.
func DefaultRegistry() *Registry {
	return NewRegistry(
		NewCommandInjectionRule(),
		NewSQLInjectionRule(),
		NewPathTraversalRule(),
		NewHardcodedSecretRule(),
		NewDeserializationRule(),
	)
}
