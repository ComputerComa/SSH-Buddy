package agent

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func (e *env) run() int { return e.agent.Run(context.Background()) }

func (e *env) credFile() string  { return filepath.Join(e.agent.Paths.StateDir, "machine-credential") }
func (e *env) nonceFile() string { return filepath.Join(e.agent.Paths.StateDir, "enroll-nonce") }

func TestFirstRunSyncsThenEnrollsThenReportsHealthy(t *testing.T) {
	e := newEnv(t)
	body := list(newKey(t))
	e.srv.set(func(f *fakeServer) { f.keyBody = body })

	if code := e.run(); code != ExitOK {
		t.Fatalf("exit %d\n%s", code, e.log)
	}
	if e.managed() != body {
		t.Fatal("keys not installed")
	}
	_, enrolls, checkins := e.srv.snapshot()
	if len(enrolls) != 1 || len(checkins) != 1 {
		t.Fatalf("enrolls=%d checkins=%d", len(enrolls), len(checkins))
	}
	en := enrolls[0]
	if en["fqdn"] != "web1.example.com" || en["agentVersion"] != "9.9.9-test" || len(en["nonce"]) < 22 {
		t.Errorf("enroll payload = %v", en)
	}
	if en["_auth"] != "Bearer sbt_template_credential_value_0123456789" {
		t.Errorf("enroll must use the template credential, got %q", en["_auth"])
	}
	ci := checkins[0]
	if ci.Auth != "Bearer "+e.srv.credential {
		t.Errorf("check-in must use the machine credential, got %q", ci.Auth)
	}
	if ci.Payload["result"] != "success" || ci.Payload["appliedEtag"] != etagOf(body) || ci.Payload["agentVersion"] != "9.9.9-test" {
		t.Errorf("check-in payload = %v", ci.Payload)
	}

	fi, err := os.Stat(e.credFile())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("machine credential file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(e.credFile()); strings.TrimSpace(string(b)) != e.srv.credential {
		t.Error("credential not stored")
	}
	if _, err := os.Stat(e.nonceFile()); !os.IsNotExist(err) {
		t.Error("the nonce must be removed after the first successful check-in")
	}
}

func TestPlainHTTPOriginSyncsEnrollsAndReports(t *testing.T) {
	e := newEnv(t)
	plain := newFakeServerOn(t, httptest.NewServer)
	e.srv, e.agent.Config.BaseURL = plain, plain.URL
	body := list(newKey(t))
	plain.set(func(f *fakeServer) { f.keyBody = body })

	if code := e.run(); code != ExitOK {
		t.Fatalf("exit %d\n%s", code, e.log)
	}
	if e.managed() != body {
		t.Fatal("keys not installed")
	}
	if _, enrolls, checkins := plain.snapshot(); len(enrolls) != 1 || len(checkins) != 1 {
		t.Fatalf("enrolls=%d checkins=%d", len(enrolls), len(checkins))
	}
}

func TestNothingIsRegisteredUntilAFirstSyncSucceeds(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyStatus = 500 })
	if code := e.run(); code != ExitSyncFailed {
		t.Fatalf("exit %d", code)
	}
	_, enrolls, checkins := e.srv.snapshot()
	if len(enrolls)+len(checkins) != 0 {
		t.Errorf("registered before any successful sync: %d enrolls, %d check-ins", len(enrolls), len(checkins))
	}
	if _, err := os.Stat(e.credFile()); !os.IsNotExist(err) {
		t.Error("credential created")
	}

	e.srv.set(func(f *fakeServer) { f.keyStatus = 0; f.keyBody = list(newKey(t)) })
	if code := e.run(); code != ExitOK {
		t.Fatalf("exit %d\n%s", code, e.log)
	}
	_, enrolls, _ = e.srv.snapshot()
	if len(enrolls) != 1 {
		t.Errorf("enrolls=%d", len(enrolls))
	}
}

func TestEveryRunReportsIncludingUnchangedAndFailedSyncs(t *testing.T) {
	e := newEnv(t)
	body := list(newKey(t))
	e.srv.set(func(f *fakeServer) { f.keyBody = body })
	e.run() // enrolls + reports

	if code := e.run(); code != ExitOK { // 304
		t.Fatalf("exit %d", code)
	}
	_, enrolls, checkins := e.srv.snapshot()
	if len(enrolls) != 1 {
		t.Errorf("enrolled again: %d", len(enrolls))
	}
	if len(checkins) != 2 || checkins[1].Payload["result"] != "success" || checkins[1].Payload["appliedEtag"] != etagOf(body) {
		t.Fatalf("unchanged sync must still report: %+v", checkins)
	}

	e.srv.set(func(f *fakeServer) { f.keyStatus = 503 })
	if code := e.run(); code != ExitSyncFailed {
		t.Fatalf("exit %d", code)
	}
	_, _, checkins = e.srv.snapshot()
	last := checkins[len(checkins)-1].Payload
	if len(checkins) != 3 || last["result"] != "error" || !strings.Contains(last["error"], "503") {
		t.Fatalf("failed sync must be reported: %+v", last)
	}
	if last["appliedEtag"] != etagOf(body) {
		t.Errorf("the still-applied revision should be reported on failure, got %q", last["appliedEtag"])
	}
	if e.managed() != body {
		t.Error("keys lost")
	}
}

func TestReportingFailureNeverUndoesAKeyUpdate(t *testing.T) {
	for name, breakReporting := range map[string]func(f *fakeServer){
		"check-in 500":     func(f *fakeServer) { f.checkinCode = 500 },
		"check-in 429":     func(f *fakeServer) { f.checkinCode = 429 },
		"enroll refused":   func(f *fakeServer) { f.enrollCode = 409 },
		"enroll forbidden": func(f *fakeServer) { f.enrollCode = 401 },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.srv.set(breakReporting)
			first := list(newKey(t))
			e.srv.set(func(f *fakeServer) { f.keyBody = first })
			if code := e.run(); code != ExitReportFailed {
				t.Fatalf("exit %d\n%s", code, e.log)
			}
			if e.managed() != first {
				t.Fatal("key update was lost because reporting failed")
			}
			// keys keep updating while reporting stays broken
			second := list(newKey(t), newKey(t))
			e.srv.set(func(f *fakeServer) { f.keyBody = second })
			if code := e.run(); code != ExitReportFailed {
				t.Fatalf("exit %d", code)
			}
			if e.managed() != second {
				t.Fatal("sync stopped working while reporting was down")
			}
			if !strings.Contains(e.log.String(), "WARNING: status report failed") {
				t.Error("report failure should be logged as a warning")
			}
		})
	}
}

func TestReportingUnreachableStillSyncs(t *testing.T) {
	// the key endpoint works, but the reporting endpoints cannot be reached at all
	e := newEnv(t)
	body := list(newKey(t))
	e.srv.set(func(f *fakeServer) { f.keyBody = body })
	_, err := e.agent.Sync(context.Background()) // first sync succeeds, as it must before any registration
	must(t, err)
	e.srv.set(func(f *fakeServer) { f.checkinCode = 502; f.enrollCode = 502 })
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	want := e.srv.keyBody
	if code := e.run(); code != ExitReportFailed {
		t.Fatalf("exit %d", code)
	}
	if e.managed() != want {
		t.Error("sync result lost")
	}
}

func TestInterruptedEnrollmentIsRecoveredWithTheSameNonce(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)); f.dropNextEnrollResponse = true })

	if code := e.run(); code != ExitReportFailed {
		t.Fatalf("exit %d\n%s", code, e.log)
	}
	if _, err := os.Stat(e.credFile()); !os.IsNotExist(err) {
		t.Fatal("a credential file exists although the response was lost")
	}
	nonce1, err := os.ReadFile(e.nonceFile())
	if err != nil {
		t.Fatal("the nonce must be persisted before the request is sent")
	}
	if fi, _ := os.Stat(e.nonceFile()); fi.Mode().Perm() != 0o600 {
		t.Errorf("nonce mode %v", fi.Mode().Perm())
	}

	if code := e.run(); code != ExitOK {
		t.Fatalf("retry exit %d\n%s", code, e.log)
	}
	_, enrolls, checkins := e.srv.snapshot()
	if len(enrolls) != 2 || enrolls[0]["nonce"] != enrolls[1]["nonce"] || enrolls[0]["nonce"] != strings.TrimSpace(string(nonce1)) {
		t.Errorf("the retry must carry the same nonce: %v", enrolls)
	}
	if len(checkins) != 1 {
		t.Errorf("checkins=%d", len(checkins))
	}
	if _, err := os.Stat(e.nonceFile()); !os.IsNotExist(err) {
		t.Error("nonce should be gone after confirmation")
	}
}

func TestAnExistingCredentialIsNeverReplacedByANewEnrollment(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	e.run()
	before, _ := os.ReadFile(e.credFile())

	e.srv.set(func(f *fakeServer) { f.credential = "sbm_a_different_credential_that_must_not_be_saved_0000" })
	e.run()
	e.run()
	after, _ := os.ReadFile(e.credFile())
	_, enrolls, _ := e.srv.snapshot()
	if string(before) != string(after) || len(enrolls) != 1 {
		t.Errorf("credential changed or re-enrolled (enrolls=%d)", len(enrolls))
	}
}

func TestARejectedCredentialAsksToEnrollButIsOnlyServedWhileAnAdministratorHasPermitted(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	e.run()
	before, _ := os.ReadFile(e.credFile())

	// An administrator removed this machine: its credential is rejected and enrollment is refused (no permit yet).
	e.srv.set(func(f *fakeServer) { f.checkinCode = 401; f.enrollCode = 409 })
	if code := e.run(); code != ExitReportFailed {
		t.Fatalf("exit %d", code)
	}
	_, enrolls, _ := e.srv.snapshot()
	if len(enrolls) != 2 {
		t.Errorf("the agent should ask exactly once per run (so the server can show 're-enrollment requested'), enrolls=%d", len(enrolls))
	}
	if after, _ := os.ReadFile(e.credFile()); string(before) != string(after) {
		t.Error("the stored credential must survive a refused re-enrollment")
	}
	if !strings.Contains(e.log.String(), "must permit it") {
		t.Errorf("the operator should be told what is needed:\n%s", e.log)
	}
	if e.managed() == "<missing>" {
		t.Error("keys must keep syncing")
	}

	// Still refused on the next run: no loop within a run, nothing replaced
	e.run()
	if _, enrolls, _ = e.srv.snapshot(); len(enrolls) != 3 {
		t.Errorf("one attempt per run, enrolls=%d", len(enrolls))
	}
}

func TestOncePermittedTheNextRunRecoversWithoutTouchingFiles(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	e.run()
	old, _ := os.ReadFile(e.credFile())

	// removed: rejected + refused
	e.srv.set(func(f *fakeServer) { f.checkinCode = 401; f.enrollCode = 409 })
	e.run()

	// the administrator permits it: the server now issues a new credential and accepts only that one
	newCred := "sbm_credential_issued_after_the_permit_0123456789abcdef"
	e.srv.set(func(f *fakeServer) {
		f.enrollCode = 0
		f.credential = newCred
		f.checkinAccepts = newCred
	})
	if code := e.run(); code != ExitOK {
		t.Fatalf("exit %d\n%s", code, e.log)
	}
	got, _ := os.ReadFile(e.credFile())
	if strings.TrimSpace(string(got)) != newCred || string(got) == string(old) {
		t.Errorf("credential file = %q", got)
	}
	if fi, _ := os.Stat(e.credFile()); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	_, _, checkins := e.srv.snapshot()
	last := checkins[len(checkins)-1]
	if last.Auth != "Bearer "+newCred || last.Payload["result"] != "success" {
		t.Errorf("the same run must report with the new credential: %+v", last)
	}
	if _, err := os.Stat(e.nonceFile()); !os.IsNotExist(err) {
		t.Error("nonce should be removed after the confirmed check-in")
	}
	// and the following run is an ordinary one: no further enrollment
	_, before, _ := e.srv.snapshot()
	e.run()
	if _, after, _ := e.srv.snapshot(); len(after) != len(before) {
		t.Error("enrolled again although the new credential works")
	}
}

func TestAServerThatKeepsRejectingTheNewCredentialDoesNotLoop(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	e.run()
	e.srv.set(func(f *fakeServer) { f.checkinCode = 401 }) // enroll succeeds, check-in still 401
	if code := e.run(); code != ExitReportFailed {
		t.Fatalf("exit %d", code)
	}
	_, enrolls, checkins := e.srv.snapshot()
	if len(enrolls) != 2 || len(checkins) != 3 {
		t.Errorf("bounded attempts expected, enrolls=%d checkins=%d", len(enrolls), len(checkins))
	}
}

func TestRemovingTheCredentialFileLetsAPermittedMachineEnrollAgain(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	e.run()
	must(t, os.Remove(e.credFile()))
	e.srv.set(func(f *fakeServer) { f.credential = "sbm_second_installation_credential_0123456789abcdef" })
	if code := e.run(); code != ExitOK {
		t.Fatalf("exit %d\n%s", code, e.log)
	}
	if b, _ := os.ReadFile(e.credFile()); strings.TrimSpace(string(b)) != "sbm_second_installation_credential_0123456789abcdef" {
		t.Error("new credential not stored")
	}
}

func TestSecretsAreNeverLogged(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	e.run()
	e.srv.set(func(f *fakeServer) { f.checkinCode = 500 })
	e.run()
	e.srv.set(func(f *fakeServer) { f.checkinCode = 401 })
	e.run()
	nonce, _ := e.srv.enrolls[0]["nonce"], 0
	for _, secret := range []string{"sbt_template_credential_value_0123456789", e.srv.credential, nonce} {
		if strings.Contains(e.log.String(), secret) {
			t.Errorf("log contains a secret:\n%s", e.log)
		}
	}
}

func TestMissingEnrollmentCredentialIsAReportingProblemNotASyncProblem(t *testing.T) {
	e := newEnv(t)
	must(t, os.Remove(e.agent.Paths.EnrollTokenFile))
	body := list(newKey(t))
	e.srv.set(func(f *fakeServer) { f.keyBody = body })
	if code := e.run(); code != ExitReportFailed {
		t.Fatalf("exit %d", code)
	}
	if e.managed() != body {
		t.Error("keys must still sync")
	}
}

func TestCredentialAndStateDirectoriesAreRootOnly(t *testing.T) {
	e := newEnv(t)
	e.srv.set(func(f *fakeServer) { f.keyBody = list(newKey(t)) })
	e.run()
	di, err := os.Stat(e.agent.Paths.StateDir)
	if err != nil || di.Mode().Perm()&0o077 != 0 {
		t.Errorf("state dir mode %v (%v)", di.Mode().Perm(), err)
	}
}
