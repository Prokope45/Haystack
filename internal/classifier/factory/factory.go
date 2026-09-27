package factory

import (
	"strings"

	"haystack/internal/classifier"
	"haystack/internal/classifier/kev"
	"haystack/internal/classifier/openrouter"
	"haystack/internal/classifier/rlcd"
	"haystack/internal/config"
)

// NewClassifier creates the appropriate Classifier implementation based on the supplied Config.
func NewClassifier(cfg *config.Config) classifier.Classifier {
	if cfg == nil {
		return kev.NewHeuristicClassifier()
	}

	fallback := kev.NewHeuristicClassifier()

	provider := strings.ToLower(strings.TrimSpace(cfg.ClassifierProvider))

	switch provider {
	case "jev", "openrouter":
		endpoint := cfg.ClassifierEndpoint
		if endpoint == "" {
			endpoint = cfg.OpenRouterBaseURL
		}
		model := cfg.ClassifierModel
		if model == "" || model == "heuristic" {
			model = cfg.OpenRouterModel
		}
		apiKey := cfg.ClassifierAPIKey
		if apiKey == "" {
			apiKey = cfg.OpenRouterAPIKey
		}
		return openrouter.NewClient(openrouter.ClientOptions{
			BaseURL:  endpoint,
			Model:    model,
			APIKey:   apiKey,
			Timeout:  cfg.ClassifierTimeout,
			Fallback: fallback,
		})

	case "kev":
		endpoint := cfg.ClassifierEndpoint
		if endpoint == "" {
			endpoint = cfg.KevEndpoint
		}
		return kev.NewLocalClient(kev.LocalClientOptions{
			Endpoint: endpoint,
			Timeout:  cfg.ClassifierTimeout,
			APIKey:   cfg.ClassifierAPIKey,
			Fallback: fallback,
		})

	case "rlcd":
		if cfg.ClassifierEndpoint != "" {
			return rlcd.NewClient(rlcd.ClientOptions{
				Endpoint: cfg.ClassifierEndpoint,
				Model:    cfg.ClassifierModel,
				APIKey:   cfg.ClassifierAPIKey,
				Timeout:  cfg.ClassifierTimeout,
				Fallback: fallback,
			})
		}
		return fallback

	case "heuristic":
		return fallback

	default:
		// Auto-detection based on configured keys / endpoints
		if cfg.OpenRouterAPIKey != "" {
			endpoint := cfg.ClassifierEndpoint
			if endpoint == "" {
				endpoint = cfg.OpenRouterBaseURL
			}
			model := cfg.ClassifierModel
			if model == "" || model == "heuristic" {
				model = cfg.OpenRouterModel
			}
			return openrouter.NewClient(openrouter.ClientOptions{
				BaseURL:  endpoint,
				Model:    model,
				APIKey:   cfg.OpenRouterAPIKey,
				Timeout:  cfg.ClassifierTimeout,
				Fallback: fallback,
			})
		}

		if cfg.ClassifierEndpoint != "" {
			return kev.NewLocalClient(kev.LocalClientOptions{
				Endpoint: cfg.ClassifierEndpoint,
				Timeout:  cfg.ClassifierTimeout,
				APIKey:   cfg.ClassifierAPIKey,
				Fallback: fallback,
			})
		}

		return fallback
	}
}
