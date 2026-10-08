package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kube-dementor/kube-dementor/pkg/api"
	"github.com/kube-dementor/kube-dementor/pkg/authcheck"
	"github.com/kube-dementor/kube-dementor/pkg/chainexploit"
	"github.com/kube-dementor/kube-dementor/pkg/config"
	"github.com/kube-dementor/kube-dementor/pkg/converter"
	"github.com/kube-dementor/kube-dementor/pkg/engine"
	"github.com/kube-dementor/kube-dementor/pkg/exploiter"
	"github.com/kube-dementor/kube-dementor/pkg/graph"
	"github.com/kube-dementor/kube-dementor/pkg/ingestor"
	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/models"
	"github.com/kube-dementor/kube-dementor/pkg/policy"
	"github.com/kube-dementor/kube-dementor/pkg/reporter"
	"github.com/kube-dementor/kube-dementor/pkg/runner"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"
	"github.com/kube-dementor/kube-dementor/pkg/scanstore"
	"github.com/kube-dementor/kube-dementor/pkg/webui"
)

func main() {
	log.SetFlags(log.LstdFlags)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "-h", "--help", "help":
		printUsage()
	case "discover":
		exitOnErr(runPhase(args, "discover"))
	case "scan":
		exitOnErr(runPhase(args, "scan"))
	case "exploit":
		exitOnErr(runPhase(args, "exploit"))
	case "contexts", "context":
		exitOnErr(runListContexts(args))
	case "chain", "autopwn":
		exitOnErr(runChain(args))
	case "web", "ui":
		exitOnErr(runWebUI(args))
	case "server", "api":
		exitOnErr(runLegacyServer(args))
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
}

func runPhase(args []string, mode string) error {
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	ctxName := fs.String("context", "", "kubeconfig context to target (default: current-context)")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	namespace := fs.String("namespace", "", "limit scan to a specific namespace")
	format := fs.String("output", "text", "text | json | html")
	outputFile := fs.String("output-file", "", "write report to this file instead of stdout")
	noColor := fs.Bool("no-color", false, "disable ANSI colour output")
	exploitLvl := fs.String("exploit-level", defaultExploitLevel(mode), "safe | read-only | intrusive")
	sevMin := fs.String("min-severity", "", "filter out findings below this severity (info|low|medium|high|critical)")
	fpFilter := fs.Bool("hide-false-positives", false, "omit findings the exploiter marked as false-positive")
	enableTrivy := fs.Bool("trivy", false, "additionally scan every pod image with Trivy (requires `trivy` on PATH)")
	enableNuclei := fs.Bool("nuclei", false, "additionally probe exposed services & API server with Nuclei (requires `nuclei` on PATH)")
	nucleiTargets := fs.String("nuclei-targets", "", "extra comma-separated URLs/IPs to hand to Nuclei")
	noGuard := fs.Bool("no-safety-guard", false, "DANGEROUS: disable the HTTP-level mutation guard")
	stealth := fs.Bool("stealth", false, "opt-in red-team extras (detection-surface probe, audit recon, MITRE ATT&CK catalog, noise self-meter). NEVER touches audit logs.")
	runtimeExtras := fs.Bool("runtime-extras", false, "extra static rules: env-secret harvest + service-mesh (Istio/Linkerd/Consul) mTLS audit")
	cniExtras := fs.Bool("cni-extras", false, "extra static rules: CNI detection + NetworkPolicy-bypass + DNS-poisoning enabler")
	exclusions := fs.String("exclusions", "", "path to a YAML or JSON exclusion file to skip expected findings (e.g. privileged pods in a known namespace)")
	refreshIntel := fs.Bool("refresh-threat-intel", true, "pull fresh Trivy DB / Nuclei templates / CISA KEV before scanning (cached, safe offline)")
	writeCSV := fs.String("csv", "", "also write a CSV report to this path")
	_ = fs.Parse(args)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	opts := runner.Options{
		Context:            *ctxName,
		Kubeconfig:         *kubeconfig,
		Namespace:          *namespace,
		Mode:               mode,
		ExploitLevel:       exploiter.ParseLevel(*exploitLvl),
		DisableSafetyGuard: *noGuard,
		TrivyEnabled:       *enableTrivy,
		NucleiEnabled:      *enableNuclei,
		Stealth:            *stealth,
		RuntimeExtras:      *runtimeExtras,
		CNIExtras:          *cniExtras,
		RefreshThreatIntel: *refreshIntel,
	}
	if *exclusions != "" {
		set, err := policy.Load(*exclusions)
		if err != nil {
			return fmt.Errorf("load exclusions: %w", err)
		}
		opts.Exclusions = set
		log.Printf("[runner] loaded %d exclusion rule(s) from %s", len(set.Entries), *exclusions)
	}
	if *nucleiTargets != "" {
		for _, t := range strings.Split(*nucleiTargets, ",") {
			if t = strings.TrimSpace(t); t != "" {
				opts.NucleiTargets = append(opts.NucleiTargets, t)
			}
		}
	}
	if mode == "scan" {
		opts.SkipExploit = true
	}

	report, err := runner.Execute(ctx, opts)
	if err != nil {
		return err
	}

	if *sevMin != "" {
		report.Findings = filterBySeverity(report.Findings, strings.ToUpper(*sevMin))
	}
	if *fpFilter {
		report.Findings = filterOutFP(report.Findings)
	}

	report.Summary = scanner.ComputeSummary(report.Findings)

	var writer = os.Stdout
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			return err
		}
		defer f.Close()
		writer = f
	}
	color := !*noColor && *outputFile == "" && isTerminal(writer)
	if err := reporter.Write(writer, report, reporter.Format(*format), color); err != nil {
		return err
	}
	if *outputFile != "" {
		log.Printf("[runner] report written: %s", *outputFile)
	}
	if *writeCSV != "" {
		f, err := os.Create(*writeCSV)
		if err != nil {
			return fmt.Errorf("create csv: %w", err)
		}
		defer f.Close()
		if err := reporter.WriteCSV(f, report); err != nil {
			return fmt.Errorf("write csv: %w", err)
		}
		log.Printf("[runner] csv written: %s", *writeCSV)
	}

	if nonZeroOnHigh(report) {
		os.Exit(3)
	}
	return nil
}

func defaultExploitLevel(mode string) string {
	if mode == "exploit" {
		return "read-only"
	}
	return "safe"
}

func filterBySeverity(fs []scanner.Finding, min string) []scanner.Finding {
	order := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	limit, ok := order[min]
	if !ok {
		return fs
	}
	out := fs[:0]
	for _, f := range fs {
		if order[string(f.Severity)] <= limit {
			out = append(out, f)
		}
	}
	return out
}

func filterOutFP(fs []scanner.Finding) []scanner.Finding {
	out := fs[:0]
	for _, f := range fs {
		if f.Exploit != nil && f.Exploit.FalsePositive {
			continue
		}
		out = append(out, f)
	}
	return out
}

func nonZeroOnHigh(r *scanner.ScanReport) bool {
	if os.Getenv("KUBE_DEMENTOR_CI_EXIT_CODE") == "" {
		return false
	}
	return r.Summary.BySeverity[scanner.SevCritical] > 0 || r.Summary.BySeverity[scanner.SevHigh] > 0
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func runChain(args []string) error {
	fs := flag.NewFlagSet("chain", flag.ExitOnError)
	ctxName := fs.String("context", "", "kubeconfig context to target")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig")
	namespace := fs.String("namespace", "", "limit to namespace (default: all)")
	format := fs.String("output", "text", "text | json")
	outputFile := fs.String("output-file", "", "write report to file")
	timeoutMins := fs.Int("timeout", 15, "max chain execution time in minutes")
	advisorProvider := fs.String("advisor", "", "LLM advisor: gemini | openai | none (default: auto-detect)")
	advisorKey := fs.String("advisor-key", "", "API key for LLM advisor (default: from env)")
	advisorURL := fs.String("advisor-url", "", "Base URL for LLM advisor API")
	advisorModel := fs.String("advisor-model", "", "LLM model name")
	_ = fs.Parse(args)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Println("═══════════════════════════════════════════════════════════════")
	log.Println("  Kube-Dementor — Autonomous Attack Chain Mode")
	log.Println("  This mode will attempt to fully compromise the cluster")
	log.Println("  by chaining exploits: privesc → escape → harvest → pivot")
	log.Println("═══════════════════════════════════════════════════════════════")

	sess, err := kubectx.Resolve(*ctxName, *kubeconfig)
	if err != nil {
		return fmt.Errorf("resolve context: %w", err)
	}
	log.Printf("[chain] Connected: context=%s cluster=%s server=%s",
		sess.Info.Name, sess.Info.ClusterName, sess.Info.ClusterServer)

	ns := *namespace
	inv, err := scanner.BuildInventory(ctx, sess, ns)
	if err != nil {
		return fmt.Errorf("build inventory: %w", err)
	}
	log.Printf("[chain] Inventory: pods=%d nodes=%d namespaces=%d",
		len(inv.Pods), len(inv.Nodes), len(inv.Namespaces))

	advisor := chainexploit.NewAdvisor(*advisorProvider, *advisorKey, *advisorURL, *advisorModel)

	eng := chainexploit.NewEngine(sess, inv, chainexploit.Options{
		Timeout: time.Duration(*timeoutMins) * time.Minute,
		Advisor: advisor,
	})

	report := eng.Run(ctx)

	var writer = os.Stdout
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			return err
		}
		defer f.Close()
		writer = f
	}

	switch *format {
	case "json":
		jsonData, jerr := json.MarshalIndent(report, "", "  ")
		if jerr != nil {
			return jerr
		}
		fmt.Fprintln(writer, string(jsonData))
	default:
		fmt.Fprintln(writer, report.ChainSummary)
		fmt.Fprintln(writer)
		fmt.Fprintf(writer, "Duration: %s\n", report.Duration)
		fmt.Fprintf(writer, "Max Access: %s\n", report.MaxAccess)
		fmt.Fprintf(writer, "Full Chain Proven: %v\n", report.FullChainProven)
		fmt.Fprintf(writer, "Steps: %d\n", len(report.Steps))
		fmt.Fprintf(writer, "Credentials: %d\n", len(report.Credentials))
		fmt.Fprintf(writer, "Findings: %d\n\n", len(report.Findings))

		for i, step := range report.Steps {
			icon := "✗"
			if step.Status == "success" {
				icon = "✓"
			}
			fmt.Fprintf(writer, "  %d. [%s] [%s] %s (%s)\n", i+1, icon, step.Phase, step.StepName, step.Duration)
			if step.Evidence != "" && step.Status == "success" {
				lines := strings.Split(step.Evidence, "\n")
				for _, l := range lines {
					if len(l) > 120 {
						l = l[:120] + "..."
					}
					fmt.Fprintf(writer, "       %s\n", l)
				}
			}
		}
	}

	if *outputFile != "" {
		log.Printf("[chain] Report written to %s", *outputFile)
	}

	return nil
}

func runListContexts(args []string) error {
	fs := flag.NewFlagSet("contexts", flag.ExitOnError)
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig")
	_ = fs.Parse(args)
	names, current, err := kubectx.ListContexts(*kubeconfig)
	if err != nil {
		return err
	}
	for _, n := range names {
		marker := "  "
		if n == current {
			marker = "* "
		}
		fmt.Println(marker + n)
	}
	return nil
}

func runWebUI(args []string) error {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	addr := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	noBrowser := fs.Bool("no-browser", false, "do not attempt to open a browser")
	liveExploit := fs.Bool("live-exploit", false,
		"enable on-demand live exploitation from the UI (pods/exec, SA token probe, secret read, etc.). Off by default.")
	allowSidecar := fs.Bool("allow-sidecar-injection", false,
		"additionally enable the sidecar-injection capability, which PATCHES a real pod. "+
			"Requires --live-exploit. Only use on lab/test clusters.")
	_ = fs.Parse(args)

	if *allowSidecar && !*liveExploit {
		return fmt.Errorf("--allow-sidecar-injection requires --live-exploit")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	srv := webui.NewServer(*addr)
	srv.AllowLiveExploit = *liveExploit
	srv.AllowSidecarInjection = *allowSidecar
	if *liveExploit {
		log.Printf("[web] LIVE-EXPLOIT MODE ENABLED — verified findings can be actively exploited from the UI")
	}
	if *allowSidecar {
		log.Printf("[web] SIDECAR-INJECTION ENABLED — verified persistence findings can inject real sidecars (USE ONLY ON LABS)")
	}
	if !*noBrowser {
		go tryOpenBrowser(*addr)
	}
	return srv.Start(ctx)
}

func tryOpenBrowser(addr string) {

	host := addr
	if strings.HasPrefix(host, ":") {
		host = "localhost" + host
	}
	url := "http://" + host + "/"
	time.Sleep(300 * time.Millisecond)
	var cmd string
	var cmdArgs []string
	switch {
	case fileExists("/usr/bin/open"), fileExists("/usr/local/bin/open"):
		cmd, cmdArgs = "open", []string{url}
	case fileExists("/usr/bin/xdg-open"):
		cmd, cmdArgs = "xdg-open", []string{url}
	default:
		log.Printf("[webui] open %s in your browser", url)
		return
	}
	if err := execCmd(cmd, cmdArgs...); err != nil {
		log.Printf("[webui] could not open browser (%v); visit %s manually", err, url)
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func execCmd(name string, args ...string) error {
	return exec.Command(name, args...).Start()
}

func runLegacyServer(_ []string) error {
	log.Println("=== Kube-Dementor server (legacy Neo4j + Web dashboard) ===")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg := config.DefaultConfig()

	scanDir := getenv("KUBE_DEMENTOR_SCAN_DIR", filepath.Join(os.TempDir(), "kube-dementor-scans"))
	scans, err := scanstore.New(scanDir)
	if err != nil {
		return err
	}
	log.Printf("Scan store: %s", scanDir)

	runScanLegacy(ctx, cfg, scans)

	listenAddr := getenv("KUBE_DEMENTOR_LISTEN", "127.0.0.1:8888")
	webDir := getenv("KUBE_DEMENTOR_WEB_DIR", "")
	if webDir == "" {
		exePath, _ := os.Executable()
		webDir = filepath.Join(filepath.Dir(exePath), "..", "..", "web", "static")
	}

	rescanFn := func(namespace, kubeconfig string) {
		rescanCfg := *cfg
		if namespace != "" {
			rescanCfg.Namespace = namespace
		}
		if kubeconfig != "" {
			rescanCfg.Kubeconfig = kubeconfig
		}
		runScanLegacy(context.Background(), &rescanCfg, scans)
	}

	apiServer, err := api.NewServer(cfg.Neo4jURI, cfg.Neo4jUser, cfg.Neo4jPassword, cfg.Neo4jDatabase, listenAddr, webDir, scans, rescanFn)
	if err != nil {
		return err
	}
	defer apiServer.Close(ctx)
	queryUser, queryPassword := os.Getenv("NEO4J_QUERY_USER"), os.Getenv("NEO4J_QUERY_PASS")
	if queryUser != "" || queryPassword != "" {
		if queryUser == "" || queryPassword == "" || queryUser == cfg.Neo4jUser {
			return fmt.Errorf("custom queries require separate NEO4J_QUERY_USER and NEO4J_QUERY_PASS credentials with read-only database privileges")
		}
		if err := apiServer.ConfigureReadOnlyQueries(cfg.Neo4jURI, queryUser, queryPassword); err != nil {
			return fmt.Errorf("configure read-only query API: %w", err)
		}
	}

	log.Println("Starting API server...")
	return apiServer.Start(ctx)
}

func runScanLegacy(ctx context.Context, cfg *config.Config, scans *scanstore.Store) {
	scanID := fmt.Sprintf("scan-%d", time.Now().UnixMilli())
	meta := &scanstore.ScanMeta{
		ID:        scanID,
		StartedAt: time.Now(),
		Namespace: cfg.Namespace,
		Status:    "running",
	}
	scans.Save(meta)

	session, err := config.NewKubeSession(cfg)
	if err != nil {
		meta.Status, meta.Error, meta.FinishedAt = "failed", err.Error(), time.Now()
		scans.Save(meta)
		log.Printf("[scan:%s] failed: %v", scanID, err)
		return
	}
	session, _, err = kubectx.WrapSessionReadOnly(session)
	if err != nil {
		meta.Status, meta.Error, meta.FinishedAt = "failed", err.Error(), time.Now()
		scans.Save(meta)
		return
	}
	clientset := session.Client
	inventory, err := scanner.BuildInventory(ctx, session, cfg.Namespace)
	if err != nil {
		meta.Status, meta.Error, meta.FinishedAt = "failed", err.Error(), time.Now()
		scans.Save(meta)
		return
	}
	raw := &ingestor.RawClusterData{
		Pods: inventory.Pods, Nodes: inventory.Nodes, ServiceAccounts: inventory.ServiceAccounts,
		Roles: inventory.Roles, ClusterRoles: inventory.ClusterRoles,
		RoleBindings: inventory.RoleBindings, ClusterRoleBindings: inventory.ClusterRoleBindings,
	}
	for _, issue := range inventory.CollectionIssues {
		meta.Warnings = append(meta.Warnings, fmt.Sprintf("%s %s namespace=%q: %s", issue.Operation, issue.Resource, issue.Namespace, issue.Error))
	}

	conv := converter.New()
	clusterData := conv.Convert(raw)
	namespaces := append([]string{cfg.Namespace}, inventory.NamespaceTargets...)
	for _, p := range clusterData.Pods {
		if p.Namespace != "" {
			namespaces = append(namespaces, p.Namespace)
		}
	}
	for _, sa := range raw.ServiceAccounts {
		namespaces = append(namespaces, sa.Namespace)
	}
	for _, role := range raw.Roles {
		namespaces = append(namespaces, role.Namespace)
	}
	for _, binding := range raw.RoleBindings {
		namespaces = append(namespaces, binding.Namespace)
	}
	if len(namespaces) == 1 && cfg.Namespace == "" {
		namespaces = append(namespaces, "default")
	}
	userPerms := authcheck.NewChecker(ctx, clientset, namespaces)
	for check, err := range userPerms.Errors {
		meta.Warnings = append(meta.Warnings, check+": "+err)
	}
	var membership []models.Edge
	operatorUID := ""
	if userPerms.User == "" {
		userPerms.User = "current credentials (authentication identity unresolved)"
		operatorUID = "operator/" + scanID
		clusterData.Identities = append(clusterData.Identities, models.IdentityNode{
			UID: operatorUID, Name: userPerms.User, Kind: models.IdentityKindOperator,
		})
	} else {
		membership = converter.AddOperator(clusterData, userPerms.User, userPerms.Groups)
		for _, identity := range clusterData.Identities {
			if identity.Kind == models.IdentityKindUser && identity.Name == userPerms.User ||
				identity.Kind == models.IdentityKindServiceAccount &&
					"system:serviceaccount:"+identity.Namespace+":"+identity.Name == userPerms.User {
				operatorUID = identity.UID
				break
			}
		}
	}
	var createNamespaces []string
	for _, ns := range userPerms.Namespaces {
		if ns != "" && userPerms.CanI("create", "pods", "", ns) {
			createNamespaces = append(createNamespaces, ns)
		}
	}
	for _, result := range scanner.AssessPodCreation(ctx, clientset, createNamespaces, raw.Nodes, true) {
		if result.Status == scanner.AdmissionUnknown {
			meta.Warnings = append(meta.Warnings, fmt.Sprintf("admission namespace=%s technique=%s: %s", result.Namespace, result.Technique, result.Reason))
		}
		if result.Status == scanner.AdmissionAdmitted {
			name := result.Technique + " (placement unverified)"
			if result.NodeName != "" {
				name = result.Technique + " targeting " + result.NodeName
			}
			clusterData.Actions = append(clusterData.Actions, models.ActionNode{
				UID:  fmt.Sprintf("action/admitted/%s/%s/%s/%s", result.Namespace, result.NodeName, result.Technique, operatorUID),
				Name: name, Namespace: result.Namespace, OwnerUID: operatorUID,
				Kind: "PodTemplate", Admission: string(result.Status), NodeName: result.NodeName, Technique: result.Technique,
			})
		}
	}
	eng := engine.New()
	edges := eng.Analyze(clusterData, userPerms)
	edges = append(edges, membership...)
	attackGraph := &models.AttackGraph{ClusterData: *clusterData, Edges: edges}

	exp := graph.New(cfg.Neo4jURI, cfg.Neo4jUser, cfg.Neo4jPassword, cfg.Neo4jDatabase)
	if err := exp.Export(ctx, attackGraph); err != nil {
		meta.Status, meta.Error, meta.FinishedAt = "failed", err.Error(), time.Now()
		scans.Save(meta)
		log.Printf("[scan:%s] neo4j export failed: %v (skipping; continue serving API)", scanID, err)
		return
	}
	meta.Status, meta.FinishedAt = "completed", time.Now()
	meta.Incomplete = len(meta.Warnings) > 0
	meta.NodeCount = len(clusterData.Identities) + len(clusterData.PermissionSets) + len(clusterData.Pods) +
		len(clusterData.Containers) + len(clusterData.Nodes) + len(clusterData.Volumes) + len(clusterData.Actions)
	meta.EdgeCount = len(edges)
	names := map[string]string{}
	for _, item := range clusterData.Identities {
		names[item.UID] = item.Name
	}
	for _, item := range clusterData.PermissionSets {
		names[item.UID] = item.Name
	}
	for _, item := range clusterData.Pods {
		names[item.UID] = item.Name
	}
	for _, item := range clusterData.Containers {
		names[item.UID] = item.Name
	}
	for _, item := range clusterData.Nodes {
		names[item.UID] = item.Name
	}
	for _, item := range clusterData.Actions {
		names[item.UID] = item.Name
	}
	results := &scanstore.ScanResults{
		Nodes: scanstore.ScanNodeSummary{
			Identities: len(clusterData.Identities), PermissionSets: len(clusterData.PermissionSets),
			Pods: len(clusterData.Pods), Containers: len(clusterData.Containers), Nodes: len(clusterData.Nodes),
			Volumes: len(clusterData.Volumes), Actions: len(clusterData.Actions),
		},
		Edges: make([]scanstore.ScanEdge, 0, len(edges)),
	}
	for _, edge := range edges {
		results.Edges = append(results.Edges, scanstore.ScanEdge{
			SourceName: names[edge.SourceUID], TargetName: names[edge.TargetUID], Type: string(edge.Type), Properties: edge.Properties,
		})
		switch edge.Properties["exploitable"] {
		case "YES":
			meta.Exploitable++
		case "NO":
			meta.NotExploit++
		case "UNCHECKED":
			meta.Unchecked++
		}
	}
	results.Meta = *meta
	if err := scans.SaveResults(scanID, results); err != nil {
		meta.Status, meta.Error = "failed", fmt.Sprintf("persist scan results: %v", err)
	}
	scans.Save(meta)
	log.Printf("[scan:%s] ok: nodes=%d edges=%d", scanID, meta.NodeCount, meta.EdgeCount)
}

func exitOnErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func printUsage() {
	fmt.Print(`Kube-Dementor — Kubernetes Security Scanner

USAGE
  kube-dementor <command> [flags]

COMMANDS
  discover     Inventory the cluster and show what the current identity can reach
  scan         Find misconfigurations and vulnerabilities (Nessus-like)
  exploit      Scan + actively verify findings to remove false-positives (CoreImpact-like)
  chain        Autonomous attack chain: privesc → escape → harvest → lateral → control-plane
  web          Launch the simple web UI (recommended for interactive use)
  contexts     List available kubeconfig contexts
  server       Start the legacy Neo4j exporter + Web UI

COMMON FLAGS
  --context <name>           kubeconfig context (default: current-context)
  --kubeconfig <path>        kubeconfig file (default: $KUBECONFIG or ~/.kube/config)
  --namespace <ns>           limit scan to one namespace
  --output  text|json|html   (default: text)
  --output-file <path>       write report to file instead of stdout
  --no-color                 disable ANSI colour output
  --trivy                    also scan every pod image with Trivy
  --nuclei                   also probe exposed services & API server with Nuclei
  --nuclei-targets <list>    comma-separated extra URLs/IPs for Nuclei
  --no-safety-guard          DANGER: disable HTTP-level mutation guard
  --stealth                  opt-in red-team extras: detect Falco/Tetragon/StackRox,
                             audit-pipeline recon, MITRE ATT&CK catalog, noise meter.
                             NEVER touches audit logs.
  --runtime-extras           static env-secret harvest + service-mesh mTLS audit
  --cni-extras               CNI detect + NetworkPolicy bypass + DNS-poisoning enabler
  --exploit-level <lvl>    safe | read-only | intrusive (exploit only)
  --min-severity <sev>     info|low|medium|high|critical
  --hide-false-positives   omit findings marked as false-positive

CHAIN FLAGS
  --timeout <minutes>      max chain execution time (default: 15)
  --advisor <provider>     LLM advisor: gemini | openai | none (default: auto-detect)
  --advisor-key <key>      API key for LLM advisor
  --advisor-model <name>   LLM model name (default: auto)

EXAMPLES
  # Autonomous attack chain (full pentest)
  kube-dementor chain --context my-cluster --timeout 30

  # Chain with Gemini advisor
  kube-dementor chain --context my-cluster --advisor gemini

  # Interactive web UI (pick context, mode, see live progress)
  kube-dementor web

  # BloodHound-like: what can I reach?
  kube-dementor discover --context my-cluster

  # Nessus-like: scan for misconfigs
  kube-dementor scan --context my-cluster --output html --output-file report.html

  # CoreImpact-like: scan + active verification
  kube-dementor exploit --context my-cluster --exploit-level read-only --hide-false-positives

  # CI mode (exit 3 on HIGH/CRITICAL)
  KUBE_DEMENTOR_CI_EXIT_CODE=1 kube-dementor exploit
`)
}
