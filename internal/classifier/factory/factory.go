package factory

import (
	"haystack/internal/classifier"
	"haystack/internal/classifier/heuristic"
	"haystack/internal/classifier/kev"
	"haystack/internal/classifier/openrouter"
	"haystack/internal/classifier/rlcd"
	"haystack/internal/config"
)

// NewClassifier creates the appropriate Classifier implementation based on the supplied Config.
func NewClassifier(cfg *config.Config) classifier.Classifier {
	if cfg == nil {
		return heuristic.NewHeuristicClassifier()
	}

	fallback := heuristic.NewHeuristicClassifier()

	provider := config.NormalizeClassifierProvider(cfg.ClassifierProvider)

	switch provider {
	case "system-one", "openrouter":
		return systemOneClient(cfg, fallback)
	case "kev":
		return kevClient(cfg, fallback)
	case "rlcd":
		return rlcdClient(cfg, fallback)
	case "heuristic":
		return fallback
	default:
		return defaultClient(cfg, fallback)
	}
}

func systemOneClient(cfg *config.Config, fallback classifier.Classifier) classifier.Classifier {
	endpoint := cfg.ClassifierEndpoint
	if endpoint == "" {
		endpoint = cfg.OpenRouterBaseURL
	}
	explainerModel := cfg.OpenRouterModel
	if explainerModel == "" {
		explainerModel = "openrouter/free"
	}
	if cfg.ClassifierModel != "" && cfg.ClassifierModel != "heuristic" && cfg.ClassifierModel != "system-one" && cfg.ClassifierModel != "jev" {
		explainerModel = cfg.ClassifierModel
	}
	systemOneModel := cfg.SystemOneModel
	if systemOneModel == "" {
		systemOneModel = openrouter.SystemOneModel
	}
	apiKey := cfg.ClassifierAPIKey
	if apiKey == "" {
		apiKey = cfg.OpenRouterAPIKey
	}
	return openrouter.NewClient(openrouter.ClientOptions{
		BaseURL:        endpoint,
		SystemOneModel: systemOneModel,
		ExplainerModel: explainerModel,
		APIKey:         apiKey,
		Timeout:        cfg.ClassifierTimeout,
		Fallback:       fallback,
		Logger:         config.NewLogger(cfg.LogLevel, nil),
	})
}

func kevClient(cfg *config.Config, fallback classifier.Classifier) classifier.Classifier {
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
}

func rlcdClient(cfg *config.Config, fallback classifier.Classifier) classifier.Classifier {
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
}

func defaultClient(cfg *config.Config, fallback classifier.Classifier) classifier.Classifier {
	// Auto-detection based on configured keys / endpoints
	if cfg.OpenRouterAPIKey != "" {
		endpoint := cfg.ClassifierEndpoint
		if endpoint == "" {
			endpoint = cfg.OpenRouterBaseURL
		}
		explainerModel := cfg.OpenRouterModel
		if explainerModel == "" {
			explainerModel = "openrouter/free"
		}
		if cfg.ClassifierModel != "" && cfg.ClassifierModel != "heuristic" && cfg.ClassifierModel != "system-one" && cfg.ClassifierModel != "jev" {
			explainerModel = cfg.ClassifierModel
		}
		systemOneModel := cfg.SystemOneModel
		if systemOneModel == "" {
			systemOneModel = openrouter.SystemOneModel
		}
		return openrouter.NewClient(openrouter.ClientOptions{
			BaseURL:        endpoint,
			SystemOneModel: systemOneModel,
			ExplainerModel: explainerModel,
			APIKey:         cfg.OpenRouterAPIKey,
			Timeout:        cfg.ClassifierTimeout,
			Fallback:       fallback,
			Logger:         config.NewLogger(cfg.LogLevel, nil),
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
