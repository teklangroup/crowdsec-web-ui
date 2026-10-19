package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// Output captured from crowdsecurity/crowdsec v1.8.1.
var fakeCscli = map[string]string{
	"version":          "version: v1.8.1-909b5157\nCodename: alphaga\n",
	"lapi status":      "You can successfully interact with Local API (LAPI)\n",
	"decisions list":   `[{"id":1,"scenario":"crowdsecurity/ssh-bf","source":{"scope":"Ip","value":"203.0.113.7"},"decisions":[{"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"203.0.113.7","duration":"3h59m","scenario":"crowdsecurity/ssh-bf"}]}]`,
	"alerts list":      `[{"id":1,"scenario":"crowdsecurity/ssh-bf","created_at":"2026-10-19T08:29:41Z","events_count":6,"kind":"crowdsec","simulated":false,"source":{"scope":"Ip","value":"203.0.113.7","cn":"DE","as_name":"Example"}},{"id":2,"scenario":"manual","kind":"cscli","source":{"ip":"192.0.2.1"}}]`,
	"bouncers list":    `[{"name":"fw","ip_address":"127.0.0.1","type":"cs-firewall-bouncer","version":"v0.0.31","last_pull":"2026-10-19T08:30:00Z","revoked":false}]`,
	"machines list":    `[{"machineId":"localhost","ipAddress":"127.0.0.1","version":"v1.8.1","last_heartbeat":null,"isValidated":true}]`,
	"collections list": `{"collections":[{"name":"crowdsecurity/sshd","status":"enabled","local_version":"0.3"}]}`,
}

func testAgent(t *testing.T, server string) (*agent, *[][]string) {
	t.Helper()
	calls := [][]string{}
	a := newAgent(config{
		Server:    server,
		StateFile: filepath.Join(t.TempDir(), "agent.json"),
		Cscli:     []string{"docker", "exec", "crowdsec", "cscli"},
		ReloadCmd: []string{"systemctl", "reload", "crowdsec"},
		Hostname:  "web01",
	})
	a.run = func(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if name == "systemctl" {
			return nil, nil, nil
		}
		cscliArgs := args[3:]
		key := strings.Join(cscliArgs[:min(2, len(cscliArgs))], " ")
		if cscliArgs[0] == "version" {
			return nil, []byte(fakeCscli["version"]), nil
		}
		if out, ok := fakeCscli[key]; ok {
			return []byte(out), nil, nil
		}
		return []byte("ok"), nil, nil
	}
	return a, &calls
}

func TestCollectNormalizesCscliOutput(t *testing.T) {
	a, _ := testAgent(t, "")
	s := a.collect()
	if s.CrowdsecVersion != "v1.8.1-909b5157" || !s.LAPIHealthy || len(s.Errors) != 0 {
		t.Fatalf("unexpected header: %+v", s)
	}
	if s.DecisionsTotal != 1 || s.Decisions[0].Value != "203.0.113.7" {
		t.Fatalf("decisions: %+v", s.Decisions)
	}
	if len(s.Alerts) != 2 || s.Alerts[0].Country != "DE" || s.Alerts[1].SourceValue != "192.0.2.1" || s.Alerts[1].Kind != "cscli" {
		t.Fatalf("alerts: %+v", s.Alerts)
	}
	if s.Bouncers[0].IP != "127.0.0.1" || s.Machines[0].Name != "localhost" || !s.Machines[0].Validated || s.Collections[0].LocalVersion != "0.3" {
		t.Fatalf("components: %+v %+v %+v", s.Bouncers, s.Machines, s.Collections)
	}
}

func TestCollectRecordsErrorsAndEmptyLists(t *testing.T) {
	a, _ := testAgent(t, "")
	a.run = func(_ context.Context, _ string, args ...string) ([]byte, []byte, error) {
		if strings.Join(args[3:5], " ") == "decisions list" {
			return []byte("null"), nil, nil
		}
		return nil, []byte("connection refused"), errors.New("exit status 1")
	}
	s := a.collect()
	if s.LAPIHealthy || s.Errors["lapi"] == "" || s.Errors["bouncers"] == "" || s.Decisions == nil || len(s.Decisions) != 0 {
		t.Fatalf("unexpected snapshot: %+v", s)
	}
	b, _ := json.Marshal(s)
	if !strings.Contains(string(b), `"decisions":[]`) {
		t.Fatalf("empty lists must serialize as []: %s", b)
	}
}

func TestDispatchBuildsFixedArgv(t *testing.T) {
	a, calls := testAgent(t, "")
	cases := []struct {
		cmd  Command
		want string
	}{
		{Command{Action: "ban", Params: map[string]string{"target": "203.0.113.7", "duration": "2h", "reason": "fleet test"}}, "decisions add --ip 203.0.113.7 --duration 2h --reason fleet test"},
		{Command{Action: "ban", Params: map[string]string{"target": "203.0.113.9/24"}}, "decisions add --range 203.0.113.0/24 --duration 4h --reason crowdsec-web-ui fleet"},
		{Command{Action: "unban", Params: map[string]string{"target": "2001:db8::1"}}, "decisions delete --ip 2001:db8::1"},
		{Command{Action: "hub_install", Params: map[string]string{"kind": "collections", "name": "crowdsecurity/nginx", "reload": "true"}}, "collections install crowdsecurity/nginx"},
		{Command{Action: "hub_upgrade"}, "hub upgrade"},
	}
	for _, c := range cases {
		*calls = nil
		if r := a.execute(c.cmd); !r.OK {
			t.Fatalf("%s failed: %s", c.cmd.Action, r.Output)
		}
		got := strings.Join((*calls)[0][4:], " ")
		if got != c.want {
			t.Fatalf("%s: got %q want %q", c.cmd.Action, got, c.want)
		}
	}
	if last := (*calls)[len(*calls)-1]; last[0] != "docker" {
		t.Fatalf("hub_upgrade without reload must not reload: %v", *calls)
	}
}

func TestExecuteKeepsTheEndOfLongOutput(t *testing.T) {
	a, _ := testAgent(t, "")
	a.run = func(_ context.Context, name string, _ ...string) ([]byte, []byte, error) {
		if name == "systemctl" {
			return []byte("reloaded crowdsec"), nil, nil
		}
		return []byte(strings.Repeat("x", 5000)), nil, nil
	}
	r := a.execute(Command{Action: "hub_upgrade", Params: map[string]string{"reload": "true"}})
	if !r.OK || !strings.HasSuffix(r.Output, "reloaded crowdsec") || len(r.Output) > 4010 {
		t.Fatalf("unexpected output (%d bytes): ...%s", len(r.Output), r.Output[len(r.Output)-40:])
	}
}

func TestDispatchRejectsUnsafeInput(t *testing.T) {
	a, calls := testAgent(t, "")
	bad := []Command{
		{Action: "ban", Params: map[string]string{"target": "1.2.3.4; rm -rf /"}},
		{Action: "ban", Params: map[string]string{"target": "1.2.3.4", "duration": "forever"}},
		{Action: "ban", Params: map[string]string{"target": "1.2.3.4", "reason": "$(id)"}},
		{Action: "hub_install", Params: map[string]string{"kind": "binaries", "name": "x"}},
		{Action: "hub_remove", Params: map[string]string{"kind": "collections", "name": "../../etc/passwd"}},
		{Action: "hub_remove", Params: map[string]string{"kind": "collections", "name": "../x"}},
		{Action: "shell", Params: map[string]string{"cmd": "id"}},
	}
	for _, c := range bad {
		if r := a.execute(c); r.OK {
			t.Fatalf("%+v should fail", c)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("rejected commands must not run anything: %v", *calls)
	}
}

func TestEnrollAndCheckin(t *testing.T) {
	var gotCheckin checkinRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ui/api/fleet/agent/enroll":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["token"] != "secret" {
				http.Error(w, `{"error":"Invalid enrollment token"}`, http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"agent_id":"a1","key":"k1"}`))
		case "/ui/api/fleet/agent/checkin":
			if r.Header.Get("Authorization") != "Bearer k1" {
				http.Error(w, "nope", http.StatusUnauthorized)
				return
			}
			json.NewDecoder(r.Body).Decode(&gotCheckin)
			w.Write([]byte(`{"commands":[{"id":"c1","action":"refresh","params":{}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a, _ := testAgent(t, srv.URL+"/ui")
	if err := a.loadOrEnroll(); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("expected missing-token error, got %v", err)
	}
	a.cfg.EnrollToken = "wrong"
	if err := a.loadOrEnroll(); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401, got %v", err)
	}
	a.cfg.EnrollToken = "secret"
	if err := a.loadOrEnroll(); err != nil || a.state.Key != "k1" {
		t.Fatalf("enroll: %v %+v", err, a.state)
	}

	reloaded, _ := testAgent(t, srv.URL+"/ui")
	reloaded.cfg.StateFile = a.cfg.StateFile
	if err := reloaded.loadOrEnroll(); err != nil || reloaded.state.AgentID != "a1" {
		t.Fatalf("state reload: %v", err)
	}

	resp, err := a.checkin(checkinRequest{Hostname: "web01", Snapshot: a.collect()})
	if err != nil || len(resp.Commands) != 1 || resp.Commands[0].Action != "refresh" {
		t.Fatalf("checkin: %v %+v", err, resp)
	}
	if gotCheckin.Snapshot == nil || gotCheckin.Snapshot.CrowdsecVersion != "v1.8.1-909b5157" {
		t.Fatalf("server did not receive snapshot: %+v", gotCheckin)
	}
}
