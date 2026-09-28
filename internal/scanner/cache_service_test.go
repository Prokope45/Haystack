package scanner

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"sync/atomic"
	"testing"

	"haystack/internal/analyzer"
	"haystack/internal/analyzer/golang"
	"haystack/internal/buildinfo"
	"haystack/internal/cache"
	"haystack/internal/candidates"
	"haystack/internal/classifier"
	"haystack/internal/config"
	"haystack/internal/planning"
	"haystack/internal/rules"
)

type countingAnalyzer struct {
	analyzer.Analyzer
	calls atomic.Int32
}

type failingCache struct{}

func (failingCache) Get(context.Context, cache.Key) ([]byte, bool, error) {
	return nil, false, errors.New("cache unavailable")
}
func (failingCache) Put(context.Context, cache.Key, []byte, cache.Metadata) error {
	return errors.New("cache unavailable")
}
func (failingCache) Delete(context.Context, cache.Key) error { return errors.New("cache unavailable") }
func (failingCache) Clear(context.Context) error             { return errors.New("cache unavailable") }

func (a *countingAnalyzer) Analyze(ctx context.Context, code []byte, path string) ([]analyzer.Evidence, error) {
	a.calls.Add(1)
	return a.Analyzer.Analyze(ctx, code, path)
}

func TestScannerServiceCachesFinalCodeResultAndNoCacheBypasses(t *testing.T) {
	store, err := cache.NewDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := NewScannerWithCache(cacheTestConfig(), store)
	counted := &countingAnalyzer{Analyzer: golang.NewGoAnalyzer()}
	service.orch.analyzers[0] = counted
	code := []byte(`package main
import (
	"net/http"
	"os/exec"
)
func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	exec.Command("sh", "-c", cmd).Run()
}
`)
	req := ScanCodeRequest{Code: code, Language: "go", Filename: "main.go"}

	cold, err := service.ScanCode(context.Background(), req)
	if err != nil {
		t.Fatalf("cold scan failed: %v", err)
	}
	if cold.Cache.FinalResult != "MISS" || counted.calls.Load() != 1 {
		t.Fatalf("cold scan cache=%q analyzer calls=%d; want MISS and one analysis", cold.Cache.FinalResult, counted.calls.Load())
	}
	if len(cold.Findings) == 0 {
		t.Fatal("expected vulnerable source to produce a finding")
	}

	warm, err := service.ScanCode(context.Background(), req)
	if err != nil {
		t.Fatalf("warm scan failed: %v", err)
	}
	if warm.Cache.FinalResult != "HIT" || counted.calls.Load() != 1 {
		t.Fatalf("warm scan cache=%q analyzer calls=%d; want HIT and no additional analysis", warm.Cache.FinalResult, counted.calls.Load())
	}
	if !reflect.DeepEqual(cold.Findings, warm.Findings) {
		t.Fatal("cached findings differ from cold scan findings")
	}
	changedCode := append(append([]byte(nil), code...), []byte("// source changed\n")...)
	changed, err := service.ScanCode(context.Background(), ScanCodeRequest{Code: changedCode, Language: "go", Filename: "main.go"})
	if err != nil {
		t.Fatalf("changed-source scan failed: %v", err)
	}
	if changed.Cache.FinalResult != "MISS" || counted.calls.Load() != 2 {
		t.Fatalf("changed source did not invalidate final cache: cache=%q analyzer calls=%d", changed.Cache.FinalResult, counted.calls.Load())
	}

	forced, err := service.ScanCode(context.Background(), ScanCodeRequest{
		Code: code, Language: "go", Filename: "main.go", NoCache: true,
	})
	if err != nil {
		t.Fatalf("no-cache scan failed: %v", err)
	}
	if forced.Cache.FinalResult != "BYPASS" || counted.calls.Load() != 3 {
		t.Fatalf("no-cache scan cache=%q analyzer calls=%d; want BYPASS and a fresh analysis", forced.Cache.FinalResult, counted.calls.Load())
	}
}

func TestScannerServiceFindsInterproceduralGoFlowInCodeSnippet(t *testing.T) {
	service := NewScannerWithCache(cacheTestConfig(), nil)
	code := []byte(`package main
import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)
type Task struct { Script string }
func handler(w http.ResponseWriter, r *http.Request) {
	raw := requestCommand(r)
	task := buildTask(raw)
	_ = dispatchTask(task)
}
func requestCommand(r *http.Request) string { return r.URL.Query().Get("cmd") }
func normalizeCommand(value string) string { return strings.TrimSpace(fmt.Sprintf("%s", value)) }
func buildTask(value string) Task { return Task{Script: normalizeCommand(value)} }
func dispatchTask(task Task) error { return runShell(task.Script) }
func runShell(script string) error { return exec.Command("sh", "-c", script).Run() }
`)
	evidence, err := golang.NewGoAnalyzer().Analyze(context.Background(), code, "main.go")
	if err != nil || len(evidence) == 0 {
		t.Fatalf("direct Go analyzer evidence=%#v err=%v", evidence, err)
	}
	result, err := service.ScanCode(context.Background(), ScanCodeRequest{
		Code: code, Language: "go", Filename: "main.go",
	})
	if err != nil {
		t.Fatalf("interprocedural scan failed: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected one cross-function finding, got %d: %#v", len(result.Findings), result.Findings)
	}
	finding := result.Findings[0]
	if finding.RuleID != "RULE-CMD-001" {
		t.Fatalf("expected command-injection rule, got %q", finding.RuleID)
	}
	if finding.AnalysisMetadata == nil || !finding.AnalysisMetadata.Interprocedural {
		t.Fatalf("expected interprocedural analysis metadata, got %#v", finding.AnalysisMetadata)
	}
}

func TestScannerServiceFindsInterproceduralPythonFlowInCodeSnippet(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found in PATH")
	}
	service := NewScannerWithCache(cacheTestConfig(), nil)
	code := []byte(`from flask import request
import subprocess

def handler():
    command = read_command()
    dispatch(command)

def read_command():
    return request.args.get("cmd")

def dispatch(value):
    execute(value)

def execute(script):
    subprocess.run(script, shell=True)
`)
	result, err := service.ScanCode(context.Background(), ScanCodeRequest{
		Code: code, Language: "python", Filename: "app.py",
	})
	if err != nil {
		t.Fatalf("interprocedural scan failed: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected one cross-function finding, got %d: %#v", len(result.Findings), result.Findings)
	}
	if result.Findings[0].AnalysisMetadata == nil || !result.Findings[0].AnalysisMetadata.Interprocedural {
		t.Fatalf("expected interprocedural analysis metadata, got %#v", result.Findings[0].AnalysisMetadata)
	}
}

func cacheTestConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.ClassifierProvider = "heuristic"
	cfg.ClassifierModel = "heuristic"
	cfg.ClassifierEndpoint = ""
	cfg.ClassifierAPIKey = ""
	cfg.OpenRouterAPIKey = ""
	cfg.AIPlannerEnabled = false
	cfg.AIClassifierEnabled = false
	return cfg
}

func TestMalformedScanPayloadIsTreatedAsMiss(t *testing.T) {
	store, err := cache.NewDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := NewScannerWithCache(cacheTestConfig(), store)
	counted := &countingAnalyzer{Analyzer: golang.NewGoAnalyzer()}
	service.orch.analyzers[0] = counted
	req := ScanCodeRequest{Code: []byte("package main; func main() {}"), Language: "go", Filename: "main.go"}
	key, _, _, _, err := service.codeScanKey(context.Background(), service.orch.cfg, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), key, []byte(`{}`), cache.Metadata{Namespace: "scan"}); err != nil {
		t.Fatal(err)
	}
	result, err := service.ScanCode(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Cache.FinalResult != "MISS" || counted.calls.Load() != 1 {
		t.Fatalf("malformed cached result was accepted: status=%q analyzer calls=%d", result.Cache.FinalResult, counted.calls.Load())
	}
}

func TestCacheFilesystemErrorsDegradeToNormalScan(t *testing.T) {
	service := NewScannerWithCache(cacheTestConfig(), failingCache{})
	counted := &countingAnalyzer{Analyzer: golang.NewGoAnalyzer()}
	service.orch.analyzers[0] = counted
	result, err := service.ScanCode(context.Background(), ScanCodeRequest{
		Code: []byte("package main; func main() {}"), Language: "go", Filename: "main.go",
	})
	if err != nil {
		t.Fatalf("cache error prevented scan: %v", err)
	}
	if result.Cache.FinalResult != "WRITE_ERROR" || counted.calls.Load() != 1 {
		t.Fatalf("cache failure did not degrade to a scan: stats=%+v analyzer calls=%d", result.Cache, counted.calls.Load())
	}
}

type countingPlanner struct {
	calls int
	err   error
}

func (p *countingPlanner) Name() string { return "system-one" }
func (p *countingPlanner) Plan(_ context.Context, cands []candidates.AnalysisCandidate, _ planning.AnalysisBudget) (planning.AnalysisPlan, error) {
	p.calls++
	if p.err != nil {
		return planning.AnalysisPlan{}, p.err
	}
	plans := make([]planning.CandidatePlan, 0, len(cands))
	for _, candidate := range cands {
		plans = append(plans, planning.CandidatePlan{CandidateID: candidate.ID, Priority: 80, Analyze: true, Mode: planning.AnalysisDeep, PlannerProvider: "system-one", PlannerModel: "model-v1"})
	}
	return planning.AnalysisPlan{Strategy: "adaptive", Candidates: plans}, nil
}

type countingClassifier struct {
	calls int
	err   error
}

func (c *countingClassifier) ModelName() string { return "remote-test" }
func (c *countingClassifier) Classify(context.Context, classifier.ClassificationInput) (classifier.ClassificationResult, error) {
	c.calls++
	if c.err != nil {
		return classifier.ClassificationResult{}, c.err
	}
	return classifier.ClassificationResult{Model: "remote-test", Label: "command_injection", Confidence: .9, Probabilities: map[string]float64{"command_injection": .9}}, nil
}

func TestIndependentPlannerAndClassifierCaches(t *testing.T) {
	store, err := cache.NewDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	candidate := candidates.AnalysisCandidate{ID: "candidate-1", Language: "go", File: "main.go"}
	budget := planning.AnalysisBudget{MaxDepth: 8, MaxCandidates: 20}
	planner := &countingPlanner{}
	wrappedPlanner := &cachedPlanner{
		next: planner, store: store,
		identity: aiCacheIdentity{Provider: "system-one", Model: "model-v1", ModelVersion: "model-v1", PromptVersion: "prompt-v1", RequestSchemaVersion: "1", ResponseSchemaVersion: "1"},
	}
	ctx1 := context.WithValue(context.Background(), invocationStateKey{}, &invocationCacheState{})
	firstPlan, err := wrappedPlanner.Plan(ctx1, []candidates.AnalysisCandidate{candidate}, budget)
	if err != nil || len(firstPlan.Candidates) != 1 {
		t.Fatalf("first planner call result=%+v err=%v", firstPlan, err)
	}
	state2 := &invocationCacheState{}
	ctx2 := context.WithValue(context.Background(), invocationStateKey{}, state2)
	if _, err := wrappedPlanner.Plan(ctx2, []candidates.AnalysisCandidate{candidate}, budget); err != nil {
		t.Fatal(err)
	}
	if planner.calls != 1 || state2.snapshot().PlannerHits != 1 {
		t.Fatalf("planner calls=%d stats=%+v; want one provider call and a hit", planner.calls, state2.snapshot())
	}
	newPlannerModel := &cachedPlanner{
		next: planner, store: store,
		identity: aiCacheIdentity{Provider: "system-one", Model: "model-v2", ModelVersion: "model-v2", PromptVersion: "prompt-v1", RequestSchemaVersion: "1", ResponseSchemaVersion: "1"},
	}
	if _, err := newPlannerModel.Plan(context.Background(), []candidates.AnalysisCandidate{candidate}, budget); err != nil {
		t.Fatal(err)
	}
	if planner.calls != 2 {
		t.Fatalf("planner model change did not invalidate cache: calls=%d", planner.calls)
	}
	bypassPlanner := &invocationCacheState{bypass: true}
	bypassPlannerCtx := context.WithValue(context.Background(), invocationStateKey{}, bypassPlanner)
	if _, err := newPlannerModel.Plan(bypassPlannerCtx, []candidates.AnalysisCandidate{candidate}, budget); err != nil {
		t.Fatal(err)
	}
	if planner.calls != 3 || bypassPlanner.snapshot().PlannerHits != 0 || bypassPlanner.snapshot().PlannerMisses != 0 {
		t.Fatalf("planner bypass did not force provider call: calls=%d stats=%+v", planner.calls, bypassPlanner.snapshot())
	}

	baseInput := classifier.ClassificationInput{Question: "classify", Category: "command_injection", Evidence: analyzer.Evidence{File: "main.go", Code: "exec.Command(user)"}}
	classifierMock := &countingClassifier{}
	wrappedClassifier := &cachedClassifier{
		next: classifierMock, store: store,
		identity: aiCacheIdentity{Provider: "test", Model: "remote-test", ModelVersion: "remote-v1", PromptVersion: "prompt-v1", RequestSchemaVersion: "1", ResponseSchemaVersion: "1"},
	}
	if _, err := wrappedClassifier.Classify(ctx1, baseInput); err != nil {
		t.Fatal(err)
	}
	classifyState := &invocationCacheState{}
	classifyCtx := context.WithValue(context.Background(), invocationStateKey{}, classifyState)
	if _, err := wrappedClassifier.Classify(classifyCtx, baseInput); err != nil {
		t.Fatal(err)
	}
	if classifierMock.calls != 1 || classifyState.snapshot().ClassifierHits != 1 {
		t.Fatalf("classifier calls=%d stats=%+v; want one provider call and a hit", classifierMock.calls, classifyState.snapshot())
	}
	bypassClassifier := &invocationCacheState{bypass: true}
	bypassClassifierCtx := context.WithValue(context.Background(), invocationStateKey{}, bypassClassifier)
	if _, err := wrappedClassifier.Classify(bypassClassifierCtx, baseInput); err != nil {
		t.Fatal(err)
	}
	if classifierMock.calls != 2 || bypassClassifier.snapshot().ClassifierHits != 0 || bypassClassifier.snapshot().ClassifierMisses != 0 {
		t.Fatalf("classifier bypass did not force provider call: calls=%d stats=%+v", classifierMock.calls, bypassClassifier.snapshot())
	}
	baseInput.Evidence.Code += " + changed"
	if _, err := wrappedClassifier.Classify(context.Background(), baseInput); err != nil {
		t.Fatal(err)
	}
	if classifierMock.calls != 3 {
		t.Fatalf("changed evidence did not invalidate classifier cache: calls=%d", classifierMock.calls)
	}
	newModelCache := &cachedClassifier{
		next: classifierMock, store: store,
		identity: aiCacheIdentity{Provider: "test", Model: "remote-v2", ModelVersion: "remote-v2", PromptVersion: "prompt-v1", RequestSchemaVersion: "1", ResponseSchemaVersion: "1"},
	}
	if _, err := newModelCache.Classify(context.Background(), baseInput); err != nil {
		t.Fatal(err)
	}
	if classifierMock.calls != 4 {
		t.Fatalf("model change did not invalidate classifier cache: calls=%d", classifierMock.calls)
	}
}

func TestAIFailuresAreNotCached(t *testing.T) {
	store, err := cache.NewDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	classifierFailure := &countingClassifier{err: errors.New("provider unavailable")}
	wrapped := &cachedClassifier{
		next: classifierFailure, store: store,
		identity: aiCacheIdentity{Provider: "test", Model: "remote", PromptVersion: "prompt", RequestSchemaVersion: "1", ResponseSchemaVersion: "1"},
	}
	input := classifier.ClassificationInput{Question: "classify", Evidence: analyzer.Evidence{Code: "evidence"}}
	for range 2 {
		if _, err := wrapped.Classify(context.Background(), input); err == nil {
			t.Fatal("expected classifier failure")
		}
	}
	if classifierFailure.calls != 2 {
		t.Fatalf("failed classifier response was cached: calls=%d", classifierFailure.calls)
	}

	plannerFailure := &countingPlanner{err: errors.New("planner unavailable")}
	wrappedPlanner := &cachedPlanner{
		next: plannerFailure, store: store,
		identity: aiCacheIdentity{Provider: "system-one", Model: "remote", PromptVersion: "prompt", RequestSchemaVersion: "1", ResponseSchemaVersion: "1"},
	}
	for range 2 {
		if _, err := wrappedPlanner.Plan(context.Background(), nil, planning.AnalysisBudget{}); err == nil {
			t.Fatal("expected planner failure")
		}
	}
	if plannerFailure.calls != 2 {
		t.Fatalf("failed planner response was cached: calls=%d", plannerFailure.calls)
	}
}

func TestFinalScanIdentityInvalidatesBehaviorInputs(t *testing.T) {
	base := codeScanIdentity{
		ScannerVersion:          buildinfo.ScannerVersion,
		RulesVersion:            rules.RulesVersion,
		RuntimeVersion:          "go-test-version",
		PythonVersion:           "Python 3.test",
		SourceHash:              "source-hash",
		Language:                "go",
		Filename:                "main.go",
		MinSeverity:             "low",
		Strategy:                "adaptive",
		AIMode:                  "optional",
		ClassifierProvider:      "heuristic",
		ClassifierModel:         "heuristic",
		PlannerPromptVersion:    buildinfo.PlannerPromptVersion,
		PlannerSchemaVersion:    buildinfo.PlannerSchemaVersion,
		ClassifierPromptVersion: buildinfo.ClassifierPromptVersion,
		ClassifierSchemaVersion: buildinfo.ClassifierSchemaVersion,
	}
	baseKey := func(identity codeScanIdentity) cache.Key {
		key, err := makeCacheKey("scan", identity)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	original := baseKey(base)
	mutations := map[string]func(*codeScanIdentity){
		"source":          func(i *codeScanIdentity) { i.SourceHash = "different-source" },
		"language":        func(i *codeScanIdentity) { i.Language = "python" },
		"scanner version": func(i *codeScanIdentity) { i.ScannerVersion = "next" },
		"rules version":   func(i *codeScanIdentity) { i.RulesVersion = "next" },
		"strategy":        func(i *codeScanIdentity) { i.Strategy = "full" },
		"configuration":   func(i *codeScanIdentity) { i.MaxDepth++ },
		"AI mode":         func(i *codeScanIdentity) { i.AIMode = "disabled" },
		"AI credential":   func(i *codeScanIdentity) { i.PlannerCredentialConfigured = true },
		"provider":        func(i *codeScanIdentity) { i.ClassifierProvider = "remote" },
		"model":           func(i *codeScanIdentity) { i.ClassifierModel = "new-model" },
		"endpoint":        func(i *codeScanIdentity) { i.PlannerEndpoint = "https://new.example/decisions" },
		"prompt":          func(i *codeScanIdentity) { i.ClassifierPromptVersion = "next" },
		"schema":          func(i *codeScanIdentity) { i.PlannerSchemaVersion = "next" },
		"parser":          func(i *codeScanIdentity) { i.PythonVersion = "Python next" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if got := baseKey(changed); got == original {
				t.Fatalf("changing %s did not invalidate final scan key", name)
			}
		})
	}
}
