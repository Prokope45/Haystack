package rules

// RulesVersion must change whenever default rule behavior changes.
const RulesVersion = "1"

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
