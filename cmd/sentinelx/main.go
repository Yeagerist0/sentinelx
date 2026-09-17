// Command sentinelx is the single backend binary. Subcommands:
//
//	sentinelx serve   # run the API + pipeline
//	sentinelx rules   # print the loaded ruleset + MITRE coverage
//	sentinelx replay  # offline scenario replay + narrative
//	sentinelx bench   # alert reduction & precision/recall benchmark
//	sentinelx triage  # run triage agent on a scenario
//	sentinelx eval    # run held-out triage evaluation harness
//
// Rules load from --rules (default ./rules), falling back to the built-in set.
// The ingest bearer token comes from SENTINELX_TOKEN (never a config file).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"sentinelx/backend/api"
	"sentinelx/backend/bench"
	"sentinelx/backend/collect"
	"sentinelx/backend/correlate"
	"sentinelx/backend/detect"
	"sentinelx/backend/narrate"
	"sentinelx/backend/pipeline"
	"sentinelx/backend/store"
	"sentinelx/backend/tenant"
	"sentinelx/backend/triage"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sentinelx <serve|rules|replay|bench|triage|eval> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "rules":
		printRules(os.Args[2:])
	case "replay":
		replay(os.Args[2:])
	case "bench":
		runBench(os.Args[2:])
	case "triage":
		runTriage(os.Args[2:])
	case "eval":
		runEval(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func newEngine(rulesDir string) *pipeline.Engine {
	return pipeline.New(loadRules(rulesDir), newScorer())
}

// replay ingests a scenario file offline and prints the resulting
// investigations plus a grounded narrative for each.
func replay(args []string) {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	rulesDir := fs.String("rules", "./rules", "detection rules directory")
	fs.Parse(args)
	if fs.NArg() < 1 {
		log.Fatal("usage: sentinelx replay [--rules dir] <scenario.json>")
	}
	rc, err := collect.ReplayFile(fs.Arg(0))
	if err != nil {
		log.Fatalf("replay: %v", err)
	}
	eng := newEngine(*rulesDir)
	if err := rc.Run(pipeline.DefaultTenant, eng); err != nil {
		log.Fatalf("replay: %v", err)
	}
	invs := eng.Invs.ListByTenant(pipeline.DefaultTenant)
	fmt.Printf("%d event(s) -> %d investigation(s)\n", eng.Stats(pipeline.DefaultTenant).Events, len(invs))
	for _, inv := range invs {
		nar := narrate.New(nil).Render(narrate.ViewFrom(inv, eng.Events))
		fmt.Printf("\n#%d  risk=%d  techniques=%v  detections=%d  events=%d\n",
			inv.ID, inv.RiskScore, inv.TechniqueSet, len(inv.Detections), len(inv.EventIDs))
		fmt.Printf("  narrative: %s\n", nar.Text())
	}
}

func runTriage(args []string) {
	fs := flag.NewFlagSet("triage", flag.ExitOnError)
	rulesDir := fs.String("rules", "./rules", "detection rules directory")
	trace := fs.Bool("trace", false, "display the triage agent tool-using loop trace")
	fs.Parse(args)
	if fs.NArg() < 1 {
		log.Fatal("usage: sentinelx triage [--rules dir] [--trace] <scenario.json>")
	}
	rc, err := collect.ReplayFile(fs.Arg(0))
	if err != nil {
		log.Fatalf("triage: %v", err)
	}
	eng := newEngine(*rulesDir)
	if err := rc.Run(pipeline.DefaultTenant, eng); err != nil {
		log.Fatalf("triage: %v", err)
	}
	invs := eng.Invs.ListByTenant(pipeline.DefaultTenant)
	if len(invs) == 0 {
		fmt.Println("No investigations produced for this scenario.")
		return
	}
	agent := triage.NewAgent(nil)
	ctx := context.Background()
	verdict, err := agent.Triage(ctx, pipeline.DefaultTenant, invs[0], eng.Events, eng.Invs)
	if err != nil {
		log.Fatalf("triage execution failed: %v", err)
	}
	if !*trace {
		verdict.Trace = nil // hide trace in compact output unless requested
	}
	out, _ := json.MarshalIndent(verdict, "", "  ")
	fmt.Println(string(out))
}

func runEval(args []string) {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	dir := fs.String("dir", "", "eval scenario directory (empty for hand-labeled corpus)")
	rulesDir := fs.String("rules", "./rules", "detection rules directory")
	mode := fs.String("mode", "full_sandbox", "triage mode: graph_only (spine) or full_sandbox (rigor)")
	fs.Parse(args)
	scenarios, err := triage.LoadCorpus(*dir)
	if err != nil {
		log.Fatalf("eval load: %v", err)
	}
	agent := triage.NewAgent(nil)
	if *mode == "graph_only" {
		agent.Mode = triage.ModeGraphOnly
	}
	harness := triage.NewEvalHarness(agent, func() *pipeline.Engine {
		return newEngine(*rulesDir)
	})
	ctx := context.Background()
	report, err := harness.RunEval(ctx, scenarios)
	if err != nil {
		log.Fatalf("eval failed: %v", err)
	}
	fmt.Print(report.String())
}

func runBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	dir := fs.String("dir", "./tests/scenarios/bench", "scenario directory")
	rulesDir := fs.String("rules", "./rules", "detection rules directory")
	fs.Parse(args)
	scen, err := bench.LoadDir(*dir)
	if err != nil {
		log.Fatalf("bench: %v", err)
	}
	rep := bench.Run(scen, func() *pipeline.Engine { return newEngine(*rulesDir) })
	fmt.Print(rep.String())
}

func loadRules(dir string) *detect.Engine {
	if dir != "" {
		if eng, err := detect.Load(dir); err == nil && len(eng.Techniques()) > 0 {
			return eng
		} else if err != nil {
			log.Printf("rules: %v — falling back to built-in set", err)
		}
	}
	eng, err := detect.NewEngine(detect.Default())
	if err != nil {
		log.Fatalf("built-in rules failed to compile: %v", err)
	}
	return eng
}

func newScorer() *correlate.Scorer {
	s := correlate.NewScorer()
	s.CtxMult["T1204.002"] = 1.15 // exec-from-tmp gets a context bump
	return s
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	rulesDir := fs.String("rules", "./rules", "detection rules directory")
	uiDir := fs.String("ui", "./frontend", "static UI directory (empty to disable)")
	fs.Parse(args)

	rules, scorer := loadRules(*rulesDir), newScorer()

	var eng *pipeline.Engine
	if dsn := os.Getenv("SENTINELX_PG"); dsn != "" {
		pg, err := store.OpenPG(context.Background(), dsn)
		if err != nil {
			log.Fatalf("postgres: %v", err)
		}
		events := pg.Events()
		eng = pipeline.NewWithStores(rules, scorer, events, pg.Investigations())
		// Rewarm: replay persisted events so the in-memory provenance graph and
		// investigations survive a restart.
		if prior, err := events.All(); err != nil {
			log.Fatalf("postgres rewarm: %v", err)
		} else if len(prior) > 0 {
			eng.Rewarm(prior)
			log.Printf("rewarmed %d event(s) from postgres", len(prior))
		}
		log.Printf("persistence: postgres")
	} else {
		eng = pipeline.New(rules, scorer)
		log.Printf("persistence: in-memory")
	}

	tenants := loadTenants()
	srv := api.New(eng, tenants)
	srv.UIDir = *uiDir
	log.Printf("sentinelx serving on %s (rules=%s, ui=%s, tenants=%d)", *addr, *rulesDir, *uiDir, len(tenants.List()))
	log.Fatal(http.ListenAndServe(*addr, srv.Routes()))
}

// loadTenants builds the tenant store from SENTINELX_TENANTS
// ("id:name:token,id:name:token,..."), or falls back to a single tenant using
// the legacy SENTINELX_TOKEN env var (id/name = pipeline.DefaultTenant) so
// existing single-tenant deployments and the demo keep working unchanged.
func loadTenants() *tenant.Store {
	if raw := os.Getenv("SENTINELX_TENANTS"); raw != "" {
		var ts []tenant.Tenant
		for _, entry := range strings.Split(raw, ",") {
			parts := strings.SplitN(entry, ":", 3)
			if len(parts) != 3 {
				log.Fatalf("SENTINELX_TENANTS: bad entry %q, want id:name:token", entry)
			}
			ts = append(ts, tenant.Tenant{ID: parts[0], Name: parts[1], Token: parts[2]})
		}
		return tenant.NewStore(ts)
	}
	return tenant.NewStore([]tenant.Tenant{
		{ID: pipeline.DefaultTenant, Name: pipeline.DefaultTenant, Token: os.Getenv("SENTINELX_TOKEN")},
	})
}

func printRules(args []string) {
	fs := flag.NewFlagSet("rules", flag.ExitOnError)
	rulesDir := fs.String("rules", "./rules", "detection rules directory")
	fs.Parse(args)
	eng := loadRules(*rulesDir)
	techs := eng.Techniques()
	fmt.Printf("MITRE ATT&CK coverage: %d techniques\n", len(techs))
	for _, t := range techs {
		fmt.Printf("  - %s\n", t)
	}
}
