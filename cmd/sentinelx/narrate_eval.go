package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"sentinelx/backend/bench"
	"sentinelx/backend/narrate"
	"sentinelx/backend/pipeline"
	"sentinelx/backend/redteam"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// runNarrateEval red-teams an LLM narrator with the prompt-injection corpus.
// Configuration comes from the environment (never from flags, so keys stay out
// of shell history): NARRATOR_API_KEY, NARRATOR_BASE_URL, NARRATOR_MODEL,
// NARRATOR_REASONING_EFFORT, NARRATOR_PROMPT (hardened|naive).
func runNarrateEval(args []string) {
	fs := flag.NewFlagSet("narrate-eval", flag.ExitOnError)
	rulesDir := fs.String("rules", "./rules", "detection rules directory")
	scDir := fs.String("scenarios", "./tests/redteam/scenarios", "directory of malicious scenarios")
	payloads := fs.String("payloads", "./tests/redteam/payloads.json", "injection corpus (JSON)")
	repeats := fs.Int("repeats", 2, "clean baseline runs per scenario")
	maxTrials := fs.Int("max-trials", 0, "stop after this many valid injected trials (0 = all)")
	pause := fs.Duration("pause", 1500*time.Millisecond, "pause between model calls")
	out := fs.String("out", "", "write the full JSON report here")
	only := fs.String("only", "", "comma-separated payload ids to run (default: all)")
	dry := fs.Bool("dry-run", false, "evaluate the deterministic GroundedModel (no network, no API key)")
	fs.Parse(args)

	scenarios, err := bench.LoadDir(*scDir)
	if err != nil {
		log.Fatalf("narrate-eval: scenarios: %v", err)
	}
	pf, err := redteam.LoadPayloads(*payloads)
	if err != nil {
		log.Fatalf("narrate-eval: payloads: %v", err)
	}

	var model narrate.Model = narrate.GroundedModel{}
	name, style := "GroundedModel (deterministic)", "n/a"
	if !*dry {
		key := os.Getenv("NARRATOR_API_KEY")
		if key == "" {
			log.Fatal("narrate-eval: set NARRATOR_API_KEY (or use --dry-run)")
		}
		style = envOr("NARRATOR_PROMPT", "hardened")
		llm := &narrate.LLMModel{
			BaseURL:         envOr("NARRATOR_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai"),
			APIKey:          key,
			ModelName:       envOr("NARRATOR_MODEL", "gemini-3.1-flash-lite"),
			ReasoningEffort: envOr("NARRATOR_REASONING_EFFORT", "none"),
			PromptStyle:     style,
		}
		model, name = llm, llm.ModelName
	}

	onlyIDs := map[string]bool{}
	for _, id := range strings.Split(*only, ",") {
		if id = strings.TrimSpace(id); id != "" {
			onlyIDs[id] = true
		}
	}
	rep := redteam.Run(scenarios, pf, redteam.Config{
		NewEngine: func() *pipeline.Engine { return newEngine(*rulesDir) },
		Model:     model,
		Repeats:   *repeats,
		MaxTrials: *maxTrials,
		OnlyIDs:   onlyIDs,
		Pause:     *pause,
		Progress:  os.Stderr,
	})
	rep.Model, rep.PromptStyle = name, style
	// A run where many calls failed measures the failures, not the model.
	if rep.ModelCalls > 0 && rep.ModelFailures*20 > rep.ModelCalls {
		fmt.Printf("INVALID RUN: %d of %d model calls failed. These are not results; rerun when the provider's rate limit allows.\n", rep.ModelFailures, rep.ModelCalls)
		os.Exit(1)
	}
	fmt.Print(rep.Markdown())
	if *out != "" {
		b, _ := json.MarshalIndent(rep, "", " ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			log.Fatalf("narrate-eval: %v", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
	}
}
