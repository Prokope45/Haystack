package factory

import (
	"testing"

	"haystack/internal/config"
)

func TestFactoryJevProvider(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ClassifierProvider = "jev"
	cfg.OpenRouterAPIKey = "test-sk"
	cfg.OpenRouterModel = "openrouter/free"

	cls := NewClassifier(cfg)
	if cls == nil {
		t.Fatal("expected non-nil classifier")
	}
	if cls.ModelName() != "jev" {
		t.Errorf("expected model jev, got %s", cls.ModelName())
	}
}

func TestFactoryKevProvider(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ClassifierProvider = "kev"
	cfg.KevEndpoint = "http://localhost:8080/classify"

	cls := NewClassifier(cfg)
	if cls == nil {
		t.Fatal("expected non-nil classifier")
	}
	if cls.ModelName() != "kev" {
		t.Errorf("expected model kev, got %s", cls.ModelName())
	}
}

func TestFactoryHeuristicProvider(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ClassifierProvider = "heuristic"

	cls := NewClassifier(cfg)
	if cls == nil {
		t.Fatal("expected non-nil classifier")
	}
	if cls.ModelName() != "heuristic" {
		t.Errorf("expected model heuristic, got %s", cls.ModelName())
	}
}
