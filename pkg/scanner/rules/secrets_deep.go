package rules

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/kube-dementor/kube-dementor/pkg/kubectx"
	"github.com/kube-dementor/kube-dementor/pkg/scanner"

	corev1 "k8s.io/api/core/v1"
)

func SecretDeepRules() []scanner.Rule {
	return []scanner.Rule{
		{ID: "KH-SEC-DEEP-CFGMAP", Title: "ConfigMap value matches credential pattern (entropy/JWT/cloud-key)", Category: scanner.CatSecret, Fn: ruleSecretsDeepConfigMap},
		{ID: "KH-SEC-DEEP-ENV", Title: "Container env value matches credential pattern", Category: scanner.CatSecret, Fn: ruleSecretsDeepEnv},
		{ID: "KH-SEC-DEEP-ARG", Title: "Container command/args contain credential-shaped token", Category: scanner.CatSecret, Fn: ruleSecretsDeepArgs},
		{ID: "KH-SEC-DEEP-ANNOT", Title: "Annotation value matches credential pattern", Category: scanner.CatSecret, Fn: ruleSecretsDeepAnnotations},
		{ID: "KH-SEC-DEEP-CONNSTR", Title: "DB / queue connection string with embedded credentials", Category: scanner.CatSecret, Fn: ruleSecretsDeepConnStr},
		{ID: "KH-SEC-DEEP-PRIVKEY", Title: "Embedded private key (RSA/EC/OpenSSH/PGP) in workload data", Category: scanner.CatSecret, Fn: ruleSecretsDeepPrivKey},
		{ID: "KH-SEC-DEEP-GITCREDS", Title: "Git credentials URL leaked (https://user:token@host)", Category: scanner.CatSecret, Fn: ruleSecretsDeepGitCreds},
		{ID: "KH-SEC-DEEP-HELMVALS", Title: "Helm release values contain credentials in plain text", Category: scanner.CatSecret, Fn: ruleSecretsDeepHelm},
	}
}

type credPattern struct {
	id       string
	rx       *regexp.Regexp
	what     string
	min      int
	severity scanner.Severity
}

var credPatterns = []credPattern{

	{"aws-akia", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "AWS Access Key ID", 20, scanner.SevCritical},
	{"aws-asia", regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`), "AWS STS temporary access key", 20, scanner.SevHigh},
	{"aws-secret", regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?`), "AWS Secret Access Key", 40, scanner.SevCritical},
	{"gcp-sa", regexp.MustCompile(`"type"\s*:\s*"service_account"`), "GCP service-account JSON", 30, scanner.SevCritical},
	{"gcp-key", regexp.MustCompile(`"private_key_id"\s*:\s*"[a-f0-9]{40}"`), "GCP service-account key id", 50, scanner.SevCritical},
	{"azure-conn", regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{60,}`), "Azure storage connection string", 80, scanner.SevCritical},
	{"do-token", regexp.MustCompile(`\bdop_v1_[a-f0-9]{64}\b`), "DigitalOcean PAT", 70, scanner.SevHigh},

	{"gh-pat", regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`), "GitHub personal access token", 40, scanner.SevHigh},
	{"gh-app", regexp.MustCompile(`\bghu_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b`), "GitHub installation/server token", 40, scanner.SevHigh},
	{"gitlab-pat", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`), "GitLab PAT", 25, scanner.SevHigh},
	{"slack", regexp.MustCompile(`\bxox[abpors]-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+\b`), "Slack token", 40, scanner.SevHigh},
	{"npm", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), "npm publish token", 40, scanner.SevHigh},
	{"pypi", regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}\b`), "PyPI API token", 50, scanner.SevHigh},
	{"sentry", regexp.MustCompile(`\bsntrys_[A-Za-z0-9]{60,}\b`), "Sentry token", 60, scanner.SevHigh},

	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{8,}\b`), "JSON Web Token", 30, scanner.SevHigh},

	{"bearer", regexp.MustCompile(`(?i)\bAuthorization:\s*Bearer\s+[A-Za-z0-9_\-\.~+/=]{20,}\b`), "Authorization Bearer", 30, scanner.SevHigh},

	{"stripe-live", regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`), "Stripe live secret key", 32, scanner.SevCritical},
	{"stripe-test", regexp.MustCompile(`\bsk_test_[A-Za-z0-9]{24,}\b`), "Stripe test secret key", 32, scanner.SevMedium},
}

var connStringPatterns = []credPattern{
	{"pg-uri", regexp.MustCompile(`postgres(?:ql)?:\/\/[^:\s]+:[^@\s]+@[^\s/]+`), "PostgreSQL URI with credentials", 20, scanner.SevHigh},
	{"mysql-uri", regexp.MustCompile(`mysql:\/\/[^:\s]+:[^@\s]+@[^\s/]+`), "MySQL URI with credentials", 20, scanner.SevHigh},
	{"mongo-uri", regexp.MustCompile(`mongodb(?:\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\s/]+`), "MongoDB URI with credentials", 20, scanner.SevHigh},
	{"redis-uri", regexp.MustCompile(`redis(?:s)?:\/\/[^:\s]*:[^@\s]+@[^\s/]+`), "Redis URI with password", 20, scanner.SevHigh},
	{"amqp-uri", regexp.MustCompile(`amqp(?:s)?:\/\/[^:\s]+:[^@\s]+@[^\s/]+`), "AMQP URI with credentials", 20, scanner.SevHigh},
	{"http-creds", regexp.MustCompile(`https?:\/\/[A-Za-z0-9_\-\.]+:[^@\s/]+@[^\s/]+`), "HTTP(S) URL with embedded credentials", 20, scanner.SevHigh},
}

var privKeyPattern = regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY-----`)
var gitCredsPattern = regexp.MustCompile(`https?:\/\/[A-Za-z0-9_\-\.]+:[A-Za-z0-9_\-\.@%]{8,}@github\.com|https?:\/\/[A-Za-z0-9_\-\.]+:[A-Za-z0-9_\-\.@%]{8,}@gitlab\.com|https?:\/\/[A-Za-z0-9_\-\.]+:[A-Za-z0-9_\-\.@%]{8,}@bitbucket\.org`)

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	var ent float64
	n := float64(len(s))
	for _, f := range freq {
		p := float64(f) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

func looksRandom(s string) bool {
	if len(s) < 24 {
		return false
	}
	if shannonEntropy(s) < 4.0 {
		return false
	}
	var hasLow, hasUp, hasDig bool
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			hasLow = true
		case r >= 'A' && r <= 'Z':
			hasUp = true
		case r >= '0' && r <= '9':
			hasDig = true
		}
	}
	classes := 0
	if hasLow {
		classes++
	}
	if hasUp {
		classes++
	}
	if hasDig {
		classes++
	}
	return classes >= 2
}

func scanText(text string) []credPattern {
	var hits []credPattern
	for _, p := range credPatterns {
		if p.rx.MatchString(text) {
			hits = append(hits, p)
		}
	}
	return hits
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func redact(s string) string {
	if len(s) <= 6 {
		return strings.Repeat("*", len(s))
	}
	return s[:3] + strings.Repeat("*", len(s)-6) + s[len(s)-3:]
}

func ruleSecretsDeepConfigMap(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, cm := range inv.ConfigMaps {

		lname := strings.ToLower(cm.Name)
		if strings.HasPrefix(lname, "kube-root-ca") || strings.HasPrefix(lname, "istio-ca-root-cert") {
			continue
		}
		for key, val := range cm.Data {

			isURL := strings.Contains(val, "://") && !strings.Contains(val, "@")
			hasCert := strings.Contains(val, "-----BEGIN CERTIFICATE-----")
			hits := scanText(val)
			highEntropy := false
			if len(hits) == 0 && !isURL && !hasCert {

				for _, tok := range strings.FieldsFunc(val, func(r rune) bool {
					return r == ' ' || r == ',' || r == ';' || r == '\n' || r == '\t' || r == '"'
				}) {
					if looksRandom(tok) {
						highEntropy = true
						break
					}
				}
			}
			if len(hits) == 0 && !highEntropy {
				continue
			}
			what := "high-entropy random string"
			sev := scanner.SevHigh
			if len(hits) > 0 {
				what = hits[0].what
				sev = hits[0].severity
			}
			out = append(out, scanner.Finding{
				Severity:       sev,
				Title:          fmt.Sprintf("Credential-shaped value in ConfigMap %s/%s key %q", cm.Namespace, cm.Name, key),
				Description:    fmt.Sprintf("ConfigMap value matches %s. ConfigMaps are world-readable to anyone with `get configmaps` in this namespace; treat this as effectively public.", what),
				Resource:       scanner.Resource{Kind: "ConfigMap", Namespace: cm.Namespace, Name: cm.Name},
				Evidence:       fmt.Sprintf("key=%s value≈%s", key, redact(truncate(val, 80))),
				Impact:         "Any caller with `get configmaps` in this namespace can read the credential. ConfigMaps are not encrypted at rest by default.",
				Recommendation: "Move the value to a Secret with at-rest encryption, or fetch from an external vault (ESO, Vault Agent, KMS).",
				Tags:           []string{"secret", "leak", "configmap"},
			})
		}
	}
	return out
}

func ruleSecretsDeepEnv(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			for _, e := range c.Env {
				if e.ValueFrom != nil {
					continue
				}
				val := e.Value
				if val == "" {
					continue
				}
				hits := scanText(val)

				isURL := strings.Contains(val, "://")
				highEntropy := !isURL && !nameLooksTrivial(e.Name) && looksRandom(val)
				if len(hits) == 0 && !highEntropy {
					continue
				}
				what := "high-entropy random string"
				sev := scanner.SevHigh
				if len(hits) > 0 {
					what = hits[0].what
					sev = hits[0].severity
				}
				out = append(out, scanner.Finding{
					Severity:       sev,
					Title:          fmt.Sprintf("Hard-coded credential in env %q on %s/%s (%s)", e.Name, p.Namespace, p.Name, c.Name),
					Description:    fmt.Sprintf("Container env var %q has a value that matches %s. Hard-coded credentials in pod spec are visible to anyone with `get pods` and survive in deployment manifests / GitOps repos.", e.Name, what),
					Resource:       podResource(p),
					Evidence:       fmt.Sprintf("env=%s container=%s value≈%s", e.Name, c.Name, redact(truncate(val, 80))),
					Impact:         "Anyone with `get pods` (very common RBAC) sees the credential in cleartext. Backup tools, audit logs, and `kubectl describe` also surface it.",
					Recommendation: "Replace with env.valueFrom.secretKeyRef pointing to a Secret. Rotate the leaked credential.",
					Tags:           []string{"secret", "leak", "env"},
				})
			}
		}
	}
	return out
}

func nameLooksTrivial(name string) bool {
	upper := strings.ToUpper(name)
	switch upper {
	case "KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_PORT", "PATH",
		"NODE_VERSION", "GOPATH", "JAVA_HOME", "LD_LIBRARY_PATH",
		"HOME", "USER", "TZ", "LANG", "LC_ALL",
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"HTTP_PROXY_HOST", "HTTPS_PROXY_HOST",
		"GLOBAL_AGENT_HTTP_PROXY", "GLOBAL_AGENT_HTTPS_PROXY", "GLOBAL_AGENT_NO_PROXY",
		"NODE_ENV", "GO_ENV", "ENVIRONMENT", "ENV":
		return true
	}

	if strings.HasSuffix(upper, "_URL") || strings.HasSuffix(upper, "_HOST") ||
		strings.HasSuffix(upper, "_ENDPOINT") || strings.HasSuffix(upper, "_ADDR") ||
		strings.HasSuffix(upper, "_ADDRESS") || strings.HasSuffix(upper, "_DOMAIN") {
		return true
	}
	return false
}

func ruleSecretsDeepArgs(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			joined := strings.Join(append(append([]string{}, c.Command...), c.Args...), " ")
			if joined == "" {
				continue
			}
			hits := scanText(joined)
			if len(hits) == 0 {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       hits[0].severity,
				Title:          fmt.Sprintf("Credential token in container args on %s/%s (%s)", p.Namespace, p.Name, c.Name),
				Description:    fmt.Sprintf("Container command/args contain %s. CLI args are visible in `ps`, /proc/*/cmdline, audit logs, and crash dumps.", hits[0].what),
				Resource:       podResource(p),
				Evidence:       fmt.Sprintf("container=%s pattern=%s", c.Name, hits[0].id),
				Impact:         "CLI args leak through process listings, /proc, audit logs, container restarts, and core dumps.",
				Recommendation: "Pass the value via env.valueFrom.secretKeyRef or a mounted file (--config /etc/foo/secret.yaml) instead of an argument.",
				Tags:           []string{"secret", "leak", "args"},
			})
		}
	}
	return out
}

func ruleSecretsDeepAnnotations(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	check := func(kind, ns, name string, ann map[string]string) []scanner.Finding {
		var out []scanner.Finding
		for k, v := range ann {
			hits := scanText(v)
			if len(hits) == 0 {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       hits[0].severity,
				Title:          fmt.Sprintf("Credential token in annotation %q on %s %s/%s", k, kind, ns, name),
				Description:    fmt.Sprintf("Annotation value matches %s. Annotations are world-readable like the rest of the resource and are often replicated to event/audit logs.", hits[0].what),
				Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
				Evidence:       fmt.Sprintf("annotation=%s pattern=%s value≈%s", k, hits[0].id, redact(truncate(v, 80))),
				Impact:         "Annotations are visible to anyone with `get` on the resource and frequently mirrored into operator events.",
				Recommendation: "Move the secret out of annotations into a Secret reference.",
				Tags:           []string{"secret", "leak", "annotation"},
			})
		}
		return out
	}
	var out []scanner.Finding
	for _, p := range inv.Pods {
		out = append(out, check("Pod", p.Namespace, p.Name, p.Annotations)...)
	}
	for _, sa := range inv.ServiceAccounts {
		out = append(out, check("ServiceAccount", sa.Namespace, sa.Name, sa.Annotations)...)
	}
	for _, cm := range inv.ConfigMaps {
		out = append(out, check("ConfigMap", cm.Namespace, cm.Name, cm.Annotations)...)
	}
	return out
}

func ruleSecretsDeepConnStr(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	scanCS := func(text string) (credPattern, bool) {
		for _, p := range connStringPatterns {
			if p.rx.MatchString(text) {
				return p, true
			}
		}
		return credPattern{}, false
	}
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			for _, e := range c.Env {
				if e.ValueFrom != nil || e.Value == "" {
					continue
				}
				hit, ok := scanCS(e.Value)
				if !ok {
					continue
				}
				out = append(out, scanner.Finding{
					Severity:       hit.severity,
					Title:          fmt.Sprintf("Connection string with embedded credentials in env %q on %s/%s (%s)", e.Name, p.Namespace, p.Name, c.Name),
					Description:    fmt.Sprintf("env var %q is a %s.", e.Name, hit.what),
					Resource:       podResource(p),
					Evidence:       fmt.Sprintf("env=%s value≈%s", e.Name, redact(truncate(e.Value, 100))),
					Impact:         "DSN-shaped values leak full DB credentials and target host. Often re-used by attackers for lateral movement to data layers.",
					Recommendation: "Split out the password into a Secret (env.valueFrom.secretKeyRef); pass only the user/host/db in the connection string.",
					Tags:           []string{"secret", "leak", "dsn"},
				})
			}
		}
	}
	for _, cm := range inv.ConfigMaps {
		for k, v := range cm.Data {
			hit, ok := scanCS(v)
			if !ok {
				continue
			}
			out = append(out, scanner.Finding{
				Severity:       hit.severity,
				Title:          fmt.Sprintf("Connection string in ConfigMap %s/%s key %q", cm.Namespace, cm.Name, k),
				Description:    fmt.Sprintf("Key %q is a %s.", k, hit.what),
				Resource:       scanner.Resource{Kind: "ConfigMap", Namespace: cm.Namespace, Name: cm.Name},
				Evidence:       fmt.Sprintf("key=%s value≈%s", k, redact(truncate(v, 100))),
				Impact:         "ConfigMap is world-readable to anyone with `get configmaps`.",
				Recommendation: "Move the credentials portion to a Secret.",
				Tags:           []string{"secret", "leak", "dsn", "configmap"},
			})
		}
	}
	return out
}

func ruleSecretsDeepPrivKey(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	scanPriv := func(text, kind, ns, name, where string) {
		if !privKeyPattern.MatchString(text) {
			return
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevCritical,
			Title:          fmt.Sprintf("Private key embedded in %s %s/%s (%s)", kind, ns, name, where),
			Description:    "Found a `-----BEGIN ... PRIVATE KEY-----` block. Private keys should never live in ConfigMaps or pod spec; only in Secrets, ideally encrypted at rest.",
			Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
			Evidence:       fmt.Sprintf("location=%s", where),
			Impact:         "If recovered, the key allows the attacker to impersonate the workload (TLS server, SSH client, GPG signing identity, JWT signer, etc.).",
			Recommendation: "Move to a Secret. Rotate the key. Audit Git history for prior leaks.",
			Tags:           []string{"secret", "leak", "private-key"},
		})
	}
	for _, cm := range inv.ConfigMaps {
		for k, v := range cm.Data {
			scanPriv(v, "ConfigMap", cm.Namespace, cm.Name, "data."+k)
		}
	}
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			for _, e := range c.Env {
				if e.ValueFrom == nil {
					scanPriv(e.Value, "Pod", p.Namespace, p.Name, "env."+e.Name)
				}
			}
		}
	}
	return out
}

func ruleSecretsDeepGitCreds(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	emit := func(kind, ns, name, where, v string) {
		out = append(out, scanner.Finding{
			Severity:       scanner.SevCritical,
			Title:          fmt.Sprintf("Git credentials URL leaked in %s %s/%s (%s)", kind, ns, name, where),
			Description:    "Found a `https://user:token@host/repo` URL. This pattern leaks the git credential to anyone reading the resource.",
			Resource:       scanner.Resource{Kind: kind, Namespace: ns, Name: name},
			Evidence:       fmt.Sprintf("%s ≈ %s", where, redact(truncate(v, 100))),
			Impact:         "The repo PAT/password can be lifted, then used to push backdoored commits, exfil source, or pivot through GitOps controllers.",
			Recommendation: "Remove the inline credentials; use Argo CD repoCreds Secret, or git-credential-helper with a separate Secret reference.",
			Tags:           []string{"secret", "leak", "git"},
		})
	}
	for _, cm := range inv.ConfigMaps {
		for k, v := range cm.Data {
			if gitCredsPattern.MatchString(v) {
				emit("ConfigMap", cm.Namespace, cm.Name, "data."+k, v)
			}
		}
	}
	for _, p := range inv.Pods {
		for _, c := range allContainers(p) {
			for _, e := range c.Env {
				if e.ValueFrom == nil && gitCredsPattern.MatchString(e.Value) {
					emit("Pod", p.Namespace, p.Name, "env."+e.Name, e.Value)
				}
			}
			for _, a := range append(append([]string{}, c.Command...), c.Args...) {
				if gitCredsPattern.MatchString(a) {
					emit("Pod", p.Namespace, p.Name, "args["+c.Name+"]", a)
				}
			}
		}
	}
	return out
}

func ruleSecretsDeepHelm(inv *scanner.Inventory, _ *kubectx.Session) []scanner.Finding {
	var out []scanner.Finding
	for _, s := range inv.Secrets {
		if !strings.HasPrefix(s.Name, "sh.helm.release.") {
			continue
		}

		raw, ok := s.Data["release"]
		if !ok {
			continue
		}

		decoded, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			decoded = raw
		}
		hits := scanText(string(decoded))

		if len(hits) == 0 {
			var probe map[string]interface{}
			if err := json.Unmarshal(decoded, &probe); err == nil {
				flat := flatten(probe, "")
				for _, fv := range flat {
					if h := scanText(fv); len(h) > 0 {
						hits = append(hits, h...)
						break
					}
				}
			}
		}
		if len(hits) == 0 {
			continue
		}
		out = append(out, scanner.Finding{
			Severity:       scanner.SevHigh,
			Title:          fmt.Sprintf("Helm release Secret %s/%s contains credential-shaped data", s.Namespace, s.Name),
			Description:    fmt.Sprintf("The release blob in %s/%s matches %s. Anyone who can read the Helm release Secrets can recover chart values inline.", s.Namespace, s.Name, hits[0].what),
			Resource:       scanner.Resource{Kind: "Secret", Namespace: s.Namespace, Name: s.Name},
			Evidence:       fmt.Sprintf("release blob matched pattern=%s", hits[0].id),
			Impact:         "Helm release Secrets contain the *rendered values* of the chart, including any cleartext password the operator passed via --set. Read access to this Secret is read access to those values.",
			Recommendation: "Pass sensitive values via --set-file or --set-string referencing an external secret store (ESO, Vault). Restrict RBAC on Secrets named sh.helm.release.* in trusted namespaces.",
			Tags:           []string{"secret", "leak", "helm"},
		})
	}
	return out
}

func flatten(v interface{}, _ string) []string {
	switch x := v.(type) {
	case map[string]interface{}:
		var out []string
		for _, sub := range x {
			out = append(out, flatten(sub, "")...)
		}
		return out
	case []interface{}:
		var out []string
		for _, sub := range x {
			out = append(out, flatten(sub, "")...)
		}
		return out
	case string:
		return []string{x}
	default:
		return nil
	}
}

var _ corev1.Pod
