// Command crowdsec-fleet-agent reports a host's CrowdSec state to CrowdSec Web UI
// and runs the fleet actions queued there. It only makes outbound HTTPS calls.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var version = "0.2.0"

const maxDecisions = 1000

type config struct {
	Server      string
	EnrollToken string
	StateFile   string
	Cscli       []string
	ReloadCmd   []string
	Tags        []string
	Hostname    string
	Instance    string
	Interval    time.Duration
	SnapEvery   time.Duration
	Insecure    bool
}

type state struct {
	AgentID string `json:"agent_id"`
	Key     string `json:"key"`
	Server  string `json:"server"`
}

type agent struct {
	cfg    config
	state  state
	client *http.Client
	run    func(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)
}

// ---- wire types (match shared/fleet.ts) ----

type Snapshot struct {
	CollectedAt     string            `json:"collected_at"`
	CrowdsecVersion string            `json:"crowdsec_version"`
	LAPIHealthy     bool              `json:"lapi_healthy"`
	DecisionsTotal  int               `json:"decisions_total"`
	Decisions       []Decision        `json:"decisions"`
	Alerts          []Alert           `json:"alerts"`
	Bouncers        []Bouncer         `json:"bouncers"`
	Machines        []Machine         `json:"machines"`
	Collections     []HubItem         `json:"collections"`
	Errors          map[string]string `json:"errors"`
}

type Decision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

type Alert struct {
	ID          int64  `json:"id"`
	Scenario    string `json:"scenario"`
	CreatedAt   string `json:"created_at"`
	EventsCount int    `json:"events_count"`
	SourceScope string `json:"source_scope"`
	SourceValue string `json:"source_value"`
	Country     string `json:"country"`
	ASName      string `json:"as_name"`
	Kind        string `json:"kind"`
	Simulated   bool   `json:"simulated"`
}

type Bouncer struct {
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Type     string `json:"type"`
	Version  string `json:"version"`
	LastPull string `json:"last_pull"`
}

type Machine struct {
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Version       string `json:"version"`
	LastHeartbeat string `json:"last_heartbeat"`
	Validated     bool   `json:"validated"`
}

type HubItem struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	LocalVersion string `json:"local_version"`
}

type Command struct {
	ID     string            `json:"id"`
	Action string            `json:"action"`
	Params map[string]string `json:"params"`
}

type Result struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

type checkinRequest struct {
	Hostname     string    `json:"hostname"`
	AgentVersion string    `json:"agent_version"`
	Tags         []string  `json:"tags"`
	Instance     string    `json:"instance,omitempty"`
	Interval     int       `json:"interval"`
	Snapshot     *Snapshot `json:"snapshot,omitempty"`
	Results      []Result  `json:"results,omitempty"`
}

type checkinResponse struct {
	Commands []Command `json:"commands"`
}

// ---- entry point ----

func main() {
	fs := flag.NewFlagSet("crowdsec-fleet-agent", flag.ExitOnError)
	server := fs.String("server", os.Getenv("FLEET_SERVER"), "CrowdSec Web UI URL including any base path, e.g. https://crowdsec.example.com")
	token := fs.String("enroll-token", os.Getenv("FLEET_ENROLL_TOKEN"), "enrollment token from the Fleet page (first run only)")
	stateFile := fs.String("state", envOr("FLEET_STATE", "/var/lib/crowdsec-fleet/agent.json"), "where the agent stores its identity")
	cscli := fs.String("cscli", envOr("FLEET_CSCLI", "cscli"), `cscli command, e.g. "docker exec crowdsec cscli"`)
	reload := fs.String("reload-cmd", envOr("FLEET_RELOAD_CMD", "systemctl reload crowdsec"), `command that reloads CrowdSec, e.g. "docker restart crowdsec"`)
	tags := fs.String("tags", os.Getenv("FLEET_TAGS"), "comma-separated tags, e.g. web,prod,eu")
	instance := fs.String("instance", os.Getenv("FLEET_INSTANCE"), "ID of the matching LAPI instance configured in CrowdSec Web UI (optional)")
	hostname := fs.String("hostname", os.Getenv("FLEET_HOSTNAME"), "name shown in the UI (default: system hostname)")
	interval := fs.Duration("interval", 15*time.Second, "check-in interval")
	snapEvery := fs.Duration("snapshot-every", 60*time.Second, "how often to send a full status snapshot")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS certificate verification (testing only)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *server == "" {
		log.Fatal("-server (or FLEET_SERVER) is required")
	}
	if *hostname == "" {
		*hostname, _ = os.Hostname()
	}
	cfg := config{
		Server:      strings.TrimRight(*server, "/"),
		EnrollToken: *token,
		StateFile:   *stateFile,
		Cscli:       strings.Fields(*cscli),
		ReloadCmd:   strings.Fields(*reload),
		Tags:        splitTags(*tags),
		Hostname:    *hostname,
		Instance:    *instance,
		Interval:    *interval,
		SnapEvery:   *snapEvery,
		Insecure:    *insecure,
	}
	if len(cfg.Cscli) == 0 {
		log.Fatal("-cscli must not be empty")
	}
	a := newAgent(cfg)
	if err := a.loadOrEnroll(); err != nil {
		log.Fatalf("enroll: %v", err)
	}
	log.Printf("crowdsec-fleet-agent %s: host %s (%s) reporting to %s", version, a.cfg.Hostname, a.state.AgentID, a.cfg.Server)
	a.loop()
}

func newAgent(cfg config) *agent {
	return &agent{
		cfg: cfg,
		client: &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure}},
		},
		run: runCommand,
	}
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func (a *agent) loop() {
	var lastSnap time.Time
	var results []Result
	forceSnap := true
	for {
		req := checkinRequest{
			Hostname:     a.cfg.Hostname,
			AgentVersion: version,
			Tags:         a.cfg.Tags,
			Instance:     a.cfg.Instance,
			Interval:     int(a.cfg.Interval.Seconds()),
			Results:      results,
		}
		if forceSnap || time.Since(lastSnap) >= a.cfg.SnapEvery {
			req.Snapshot = a.collect()
			lastSnap = time.Now()
		}
		resp, err := a.checkin(req)
		if err != nil {
			// Results stay queued and are retried on the next check-in.
			log.Printf("check-in failed: %v", err)
			forceSnap = forceSnap || req.Snapshot != nil
			time.Sleep(a.cfg.Interval)
			continue
		}
		results, forceSnap = nil, false
		for _, c := range resp.Commands {
			r := a.execute(c)
			log.Printf("command %s %s ok=%v", c.ID, c.Action, r.OK)
			results = append(results, r)
		}
		if len(resp.Commands) > 0 {
			forceSnap = true
			continue
		}
		time.Sleep(a.cfg.Interval)
	}
}

// ---- server API ----

func (a *agent) loadOrEnroll() error {
	if b, err := os.ReadFile(a.cfg.StateFile); err == nil {
		if err := json.Unmarshal(b, &a.state); err != nil {
			return fmt.Errorf("corrupt state file %s: %w", a.cfg.StateFile, err)
		}
		if a.state.Server == a.cfg.Server && a.state.Key != "" {
			return nil
		}
	}
	if a.cfg.EnrollToken == "" {
		return errors.New("not enrolled yet: pass -enroll-token (or FLEET_ENROLL_TOKEN) on first run")
	}
	var out struct {
		AgentID string `json:"agent_id"`
		Key     string `json:"key"`
	}
	body := map[string]any{"token": a.cfg.EnrollToken, "hostname": a.cfg.Hostname, "tags": a.cfg.Tags, "instance": a.cfg.Instance}
	if err := a.post("/api/fleet/agent/enroll", "", body, &out); err != nil {
		return err
	}
	a.state = state{AgentID: out.AgentID, Key: out.Key, Server: a.cfg.Server}
	b, _ := json.MarshalIndent(a.state, "", "  ")
	if err := os.MkdirAll(filepath.Dir(a.cfg.StateFile), 0o700); err != nil {
		return err
	}
	return os.WriteFile(a.cfg.StateFile, b, 0o600)
}

func (a *agent) checkin(req checkinRequest) (*checkinResponse, error) {
	var out checkinResponse
	if err := a.post("/api/fleet/agent/checkin", a.state.Key, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (a *agent) post(path, key string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, a.cfg.Server+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "crowdsec-fleet-agent/"+version)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s %s", path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ---- collection ----

func (a *agent) cs(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	argv := append(append([]string{}, a.cfg.Cscli[1:]...), args...)
	stdout, stderr, err := a.run(ctx, a.cfg.Cscli[0], argv...)
	if err != nil {
		msg := strings.TrimSpace(string(stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(stdout))
		}
		return stdout, fmt.Errorf("%v: %s", err, truncate(msg, 400))
	}
	if len(bytes.TrimSpace(stdout)) == 0 {
		// Some cscli subcommands (e.g. version) write to stderr.
		return stderr, nil
	}
	return stdout, nil
}

func (a *agent) csJSON(v any, args ...string) error {
	out, err := a.cs(30*time.Second, args...)
	if err != nil {
		return err
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 || string(out) == "null" {
		return nil
	}
	if err := json.Unmarshal(out, v); err != nil {
		return fmt.Errorf("parse %s: %w", strings.Join(args[:2], " "), err)
	}
	return nil
}

func (a *agent) collect() *Snapshot {
	s := &Snapshot{
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		Decisions:   []Decision{},
		Alerts:      []Alert{},
		Bouncers:    []Bouncer{},
		Machines:    []Machine{},
		Collections: []HubItem{},
		Errors:      map[string]string{},
	}

	if out, err := a.cs(30*time.Second, "version"); err != nil {
		s.Errors["version"] = err.Error()
	} else {
		s.CrowdsecVersion = parseVersion(string(out))
	}

	if _, err := a.cs(30*time.Second, "lapi", "status"); err != nil {
		s.Errors["lapi"] = err.Error()
	} else {
		s.LAPIHealthy = true
	}

	// "decisions list -o json" returns alerts with their decisions nested.
	var withDecisions []rawAlert
	if err := a.csJSON(&withDecisions, "decisions", "list", "-o", "json"); err != nil {
		s.Errors["decisions"] = err.Error()
	}
	for _, ra := range withDecisions {
		for _, d := range ra.Decisions {
			s.DecisionsTotal++
			if len(s.Decisions) < maxDecisions {
				s.Decisions = append(s.Decisions, Decision(d))
			}
		}
	}

	var alerts []rawAlert
	if err := a.csJSON(&alerts, "alerts", "list", "-o", "json", "--limit", "100"); err != nil {
		s.Errors["alerts"] = err.Error()
	}
	for _, ra := range alerts {
		s.Alerts = append(s.Alerts, ra.normalize())
	}

	var bouncers []struct {
		Name     string `json:"name"`
		IP       string `json:"ip_address"`
		Type     string `json:"type"`
		Version  string `json:"version"`
		LastPull string `json:"last_pull"`
	}
	if err := a.csJSON(&bouncers, "bouncers", "list", "-o", "json"); err != nil {
		s.Errors["bouncers"] = err.Error()
	}
	for _, b := range bouncers {
		s.Bouncers = append(s.Bouncers, Bouncer(b))
	}

	var machines []struct {
		Name          string `json:"machineId"`
		IP            string `json:"ipAddress"`
		Version       string `json:"version"`
		LastHeartbeat string `json:"last_heartbeat"`
		Validated     bool   `json:"isValidated"`
	}
	if err := a.csJSON(&machines, "machines", "list", "-o", "json"); err != nil {
		s.Errors["machines"] = err.Error()
	}
	for _, m := range machines {
		s.Machines = append(s.Machines, Machine(m))
	}

	var hub struct {
		Collections []HubItem `json:"collections"`
	}
	if err := a.csJSON(&hub, "collections", "list", "-o", "json"); err != nil {
		s.Errors["collections"] = err.Error()
	}
	s.Collections = append(s.Collections, hub.Collections...)
	return s
}

func parseVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "version:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

type rawDecision struct {
	ID       int64  `json:"id"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

type rawAlert struct {
	ID          int64  `json:"id"`
	Scenario    string `json:"scenario"`
	CreatedAt   string `json:"created_at"`
	EventsCount int    `json:"events_count"`
	Kind        string `json:"kind"`
	Simulated   bool   `json:"simulated"`
	Source      struct {
		Scope  string `json:"scope"`
		Value  string `json:"value"`
		IP     string `json:"ip"`
		CN     string `json:"cn"`
		ASName string `json:"as_name"`
	} `json:"source"`
	Decisions []rawDecision `json:"decisions"`
}

func (r rawAlert) normalize() Alert {
	value := r.Source.Value
	if value == "" {
		value = r.Source.IP
	}
	return Alert{
		ID: r.ID, Scenario: r.Scenario, CreatedAt: r.CreatedAt, EventsCount: r.EventsCount,
		SourceScope: r.Source.Scope, SourceValue: value, Country: r.Source.CN, ASName: r.Source.ASName,
		Kind: r.Kind, Simulated: r.Simulated,
	}
}

// ---- command execution ----
//
// The server sends structured actions only. Every parameter is validated here
// again and mapped to a fixed cscli argv; nothing is passed through a shell.

var (
	reDuration = regexp.MustCompile(`^[0-9]{1,5}[smhd]$`)
	reHubName  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}(/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99})?$`)
	reReason   = regexp.MustCompile(`^[\pL\pN _.,:;'()/#@+-]{0,200}$`)
	hubKinds   = map[string]bool{"collections": true, "parsers": true, "scenarios": true, "postoverflows": true, "appsec-rules": true, "appsec-configs": true}
)

func (a *agent) execute(c Command) Result {
	out, err := a.dispatch(c)
	r := Result{ID: c.ID, OK: err == nil, Output: strings.TrimSpace(out)}
	if err != nil {
		r.Output = strings.TrimSpace(r.Output + "\n" + err.Error())
	}
	// cscli prints errors and the reload result last, so keep the end.
	if len(r.Output) > 4000 {
		r.Output = "…" + r.Output[len(r.Output)-4000:]
	}
	return r
}

func (a *agent) dispatch(c Command) (string, error) {
	p := c.Params
	if p == nil {
		p = map[string]string{}
	}
	long := 5 * time.Minute
	switch c.Action {
	case "refresh":
		return "status refreshed", nil

	case "ban":
		flagName, target, err := ipOrRange(p["target"])
		if err != nil {
			return "", err
		}
		duration := p["duration"]
		if duration == "" {
			duration = "4h"
		}
		if !reDuration.MatchString(duration) {
			return "", fmt.Errorf("invalid duration %q", duration)
		}
		reason := p["reason"]
		if reason == "" {
			reason = "crowdsec-web-ui fleet"
		}
		if !reReason.MatchString(reason) {
			return "", errors.New("reason contains unsupported characters")
		}
		out, err := a.cs(time.Minute, "decisions", "add", flagName, target, "--duration", duration, "--reason", reason)
		return string(out), err

	case "unban":
		flagName, target, err := ipOrRange(p["target"])
		if err != nil {
			return "", err
		}
		out, err := a.cs(time.Minute, "decisions", "delete", flagName, target)
		return string(out), err

	case "hub_update":
		out, err := a.cs(long, "hub", "update")
		return string(out), err

	case "hub_upgrade":
		out, err := a.cs(long, "hub", "upgrade")
		if err != nil {
			return string(out), err
		}
		return a.maybeReload(p, string(out))

	case "hub_install", "hub_remove":
		kind, name := p["kind"], p["name"]
		if !hubKinds[kind] {
			return "", fmt.Errorf("invalid hub item type %q", kind)
		}
		if !reHubName.MatchString(name) {
			return "", fmt.Errorf("invalid hub item name %q", name)
		}
		verb := "install"
		if c.Action == "hub_remove" {
			verb = "remove"
		}
		out, err := a.cs(long, kind, verb, name)
		if err != nil {
			return string(out), err
		}
		return a.maybeReload(p, string(out))

	case "reload":
		return a.reload()

	default:
		return "", fmt.Errorf("unsupported action %q (agent %s)", c.Action, version)
	}
}

func (a *agent) maybeReload(p map[string]string, previous string) (string, error) {
	if p["reload"] != "true" {
		return previous, nil
	}
	out, err := a.reload()
	return strings.TrimSpace(previous + "\n" + out), err
}

func (a *agent) reload() (string, error) {
	if len(a.cfg.ReloadCmd) == 0 {
		return "", errors.New("no reload command configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	stdout, stderr, err := a.run(ctx, a.cfg.ReloadCmd[0], a.cfg.ReloadCmd[1:]...)
	out := strings.TrimSpace(string(stdout) + "\n" + string(stderr))
	if out == "" && err == nil {
		out = "reloaded"
	}
	return out, err
}

func ipOrRange(v string) (string, string, error) {
	v = strings.TrimSpace(v)
	if ip := net.ParseIP(v); ip != nil {
		return "--ip", ip.String(), nil
	}
	if _, n, err := net.ParseCIDR(v); err == nil {
		return "--range", n.String(), nil
	}
	return "", "", fmt.Errorf("%q is not an IP address or CIDR range", v)
}

// ---- helpers ----

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitTags(s string) []string {
	tags := []string{}
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
