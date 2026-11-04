package main

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultAddress      = "127.0.0.1:3128"
	defaultSocksAddress = "127.0.0.1:1080"
	setupTimeout        = 30 * time.Second
)

func configExists() bool {
	if _, err := os.Stat(encryptedConfig); err == nil {
		return true
	}
	if _, err := os.Stat(plainConfig); err == nil {
		return true
	}
	return false
}

// loadConfigurationOrSetup loads an existing configuration, or runs the web
// setup wizard on first use. The master password is chosen in the browser; the
// default listeners are ready as soon as setup completes.
func loadConfigurationOrSetup() {
	if configExists() {
		loadConfiguration()
		return
	}

	if password := os.Getenv(secretEnv); password != "" {
		if err := createInitialConfig(password, defaultAddress, defaultSocksAddress); err != nil {
			log.Fatal(err)
		}
	} else if err := runSetupWizard(); err != nil {
		log.Fatal(err)
	}
	finalizeConfiguration()
}

// createInitialConfig writes the first encrypted configuration with the
// defaults and caches the derived key. It does not start any service.
func createInitialConfig(password, address, socksAddress string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("the master password must be at least %d characters", minPasswordLen)
	}
	configuration = Configuration{
		Address:        address,
		SocksAddress:   socksAddress,
		OnboardingDone: boolPtr(false),
	}
	plain, err := yaml.Marshal(configuration)
	if err != nil {
		return err
	}
	salt, err := newSecretSalt()
	if err != nil {
		return err
	}
	key, err := deriveSecretKey(password, salt)
	if err != nil {
		return err
	}
	enc, err := encryptWithKey(key, salt, plain)
	if err != nil {
		return err
	}
	if err := writeSecretFileAtomic(encryptedConfig, enc); err != nil {
		return err
	}
	setConfigCrypto(key, salt)
	saveKeyToKeychain(key, salt)
	return nil
}

func listenSetup() (net.Listener, string, error) {
	for port := 3128; port <= 3138; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			return ln, addr, nil
		}
	}
	return nil, "", errors.New("no free port for the setup page (tried 3128-3138)")
}

func pickSocksAddress() string {
	for port := 1080; port <= 1090; port++ {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			ln.Close()
			return addr
		}
	}
	return defaultSocksAddress
}

func setupToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("setup-%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// runSetupWizard serves a minimal, token-protected page on loopback and blocks
// until the user has chosen the master password.
func runSetupWizard() error {
	return runAuthWizard(setupModeCreate, nil)
}

// runMigrationWizard encrypts a legacy plaintext configuration. On a terminal
// it keeps the existing interactive prompt; when started from a desktop it uses
// the web page, because a GUI process has no usable stdin.
func runMigrationWizard() error {
	if hasTerminal() || os.Getenv(secretEnv) != "" {
		if err := migrateToEncrypted(); err != nil {
			return err
		}
		finalizeConfiguration()
		return nil
	}
	return runAuthWizard(setupModeMigrate, nil)
}

// runUnlockWizard asks for the master password in the browser when no key is
// available and the process has no terminal.
func runUnlockWizard(data []byte) error {
	return runAuthWizard(setupModeUnlock, data)
}

type setupMode string

const (
	setupModeCreate  setupMode = "create"
	setupModeMigrate setupMode = "migrate"
	setupModeUnlock  setupMode = "unlock"
)

type setupPageConfig struct {
	documentTitleKey string
	titleKey         string
	introKey         string
	submitKey        string
	successTitleKey  string
	successTextKey   string
	endpoint         string
	showConfirm      bool
	showAddresses    bool
}

func setupPageConfigFor(mode setupMode) setupPageConfig {
	switch mode {
	case setupModeMigrate:
		return setupPageConfig{
			documentTitleKey: "migrate_document_title",
			titleKey:         "migrate_title",
			introKey:         "migrate_intro",
			submitKey:        "migrate_submit",
			successTitleKey:  "migrate_success_title",
			successTextKey:   "migrate_success_text",
			endpoint:         "/api/migrate",
			showConfirm:      true,
			showAddresses:    false,
		}
	case setupModeUnlock:
		return setupPageConfig{
			documentTitleKey: "unlock_document_title",
			titleKey:         "unlock_title",
			introKey:         "unlock_intro",
			submitKey:        "unlock_submit",
			successTitleKey:  "unlock_success_title",
			successTextKey:   "unlock_success_text",
			endpoint:         "/api/unlock",
			showConfirm:      false,
			showAddresses:    false,
		}
	default:
		return setupPageConfig{
			documentTitleKey: "document_title",
			titleKey:         "title",
			introKey:         "intro",
			submitKey:        "submit",
			successTitleKey:  "success_title",
			successTextKey:   "success_text",
			endpoint:         "/api/setup",
			showConfirm:      true,
			showAddresses:    true,
		}
	}
}

// runAuthWizard starts the token-protected page used for first-run setup,
// plaintext migration and unlock. It blocks until the page completes.
func runAuthWizard(mode setupMode, data []byte) error {
	ln, addr, err := listenSetup()
	if err != nil {
		return err
	}
	token := setupToken()
	socks := pickSocksAddress()
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }

	srv := &http.Server{
		Handler:           authHandler(token, addr, socks, mode, data, finish),
		ReadHeaderTimeout: setupTimeout,
		ReadTimeout:       setupTimeout,
		WriteTimeout:      setupTimeout,
		IdleTimeout:       setupTimeout,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("setup server: %v", err)
		}
	}()

	url := fmt.Sprintf("http://%s/?token=%s", addr, token)
	switch mode {
	case setupModeUnlock:
		log.Printf("CONFIGURATION LOCKED: open %s to enter the master password", url)
	case setupModeMigrate:
		log.Printf("LEGACY CONFIGURATION: open %s to encrypt it", url)
	default:
		log.Printf("FIRST RUN: open %s to choose the master password", url)
	}
	if err := openBrowser(url); err != nil {
		log.Printf("Cannot open the browser automatically: %v", err)
	}
	<-done
	// Give the browser a moment to receive the success response before the
	// normal proxy listener takes over the same address.
	time.Sleep(700 * time.Millisecond)
	srv.Close()
	return nil
}

// setupHandler keeps the historical test entry point for the first-run page.
func setupHandler(token, address, socksAddress string, done func()) http.Handler {
	return authHandler(token, address, socksAddress, setupModeCreate, nil, done)
}

// authHandler serves the setup, migration or unlock page and performs the
// corresponding action.
func authHandler(token, address, socksAddress string, mode setupMode, data []byte, done func()) http.Handler {
	mux := http.NewServeMux()
	pageCfg := setupPageConfigFor(mode)

	validToken := func(r *http.Request) bool {
		got := r.URL.Query().Get("token")
		return subtle.ConstantTimeCompare([]byte(token), []byte(got)) == 1
	}

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if !validToken(r) {
			http.Error(w, "invalid setup token", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, renderAuthPage(pageCfg, mode, address, socksAddress))
	})

	var mu sync.Mutex
	created := false
	mux.HandleFunc("POST "+pageCfg.endpoint, func(w http.ResponseWriter, r *http.Request) {
		if !validToken(r) {
			writeSetupError(w, http.StatusForbidden, "invalid_token", "")
			return
		}
		var body struct {
			Password string `json:"password"`
			Confirm  string `json:"confirm"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
			writeSetupError(w, http.StatusBadRequest, "invalid_request", "")
			return
		}
		if mode == setupModeUnlock {
			if body.Password == "" {
				writeSetupError(w, http.StatusBadRequest, "invalid_request", "")
				return
			}
		} else {
			if len(body.Password) < minPasswordLen {
				writeSetupError(w, http.StatusBadRequest, "too_short", "")
				return
			}
			if body.Password != body.Confirm {
				writeSetupError(w, http.StatusBadRequest, "mismatch", "")
				return
			}
		}

		mu.Lock()
		if created {
			mu.Unlock()
			writeSetupError(w, http.StatusConflict, "already_completed", "")
			return
		}
		var err error
		switch mode {
		case setupModeCreate:
			err = createInitialConfig(body.Password, address, socksAddress)
		case setupModeMigrate:
			err = migrateToEncryptedWithPassword(body.Password)
			if err == nil {
				finalizeConfiguration()
			}
		case setupModeUnlock:
			err = unlockConfigWithPasswordAndApply(data, body.Password)
		}
		if err != nil {
			mu.Unlock()
			log.Printf("%s: %v", mode, err)
			code := "internal"
			status := http.StatusInternalServerError
			if errors.Is(err, errWrongPassword) {
				code = "wrong_password"
				status = http.StatusUnauthorized
			}
			writeSetupError(w, status, code, err.Error())
			return
		}
		created = true
		mu.Unlock()

		resp := map[string]string{"status": "ok"}
		if mode == setupModeCreate {
			resp["address"] = address
			resp["socks"] = socksAddress
		}
		writeSetupJSON(w, http.StatusOK, resp)
		go func() {
			time.Sleep(700 * time.Millisecond)
			done()
		}()
	})

	return mux
}

// unlockConfigWithPasswordAndApply decrypts, applies and finalizes an existing
// encrypted configuration after the user entered the master password.
func unlockConfigWithPasswordAndApply(data []byte, password string) error {
	plain, err := unlockConfigWithPassword(data, password)
	if err != nil {
		return err
	}
	return finishEncryptedConfiguration(plain)
}

// renderAuthPage fills the page template with the labels and endpoint for the
// requested mode. All user-visible strings are then resolved by the browser
// from the embedded translations.
func renderAuthPage(cfg setupPageConfig, mode setupMode, address, socksAddress string) string {
	showConfirm := "false"
	if cfg.showConfirm {
		showConfirm = "true"
	}
	showAddresses := "false"
	if cfg.showAddresses {
		showAddresses = "true"
	}
	return strings.NewReplacer(
		"__DOC_TITLE_KEY__", cfg.documentTitleKey,
		"__TITLE_KEY__", cfg.titleKey,
		"__INTRO_KEY__", cfg.introKey,
		"__PASSWORD_LABEL_KEY__", "password_label",
		"__CONFIRM_LABEL_KEY__", "confirm_label",
		"__HINT_KEY__", "password_hint",
		"__SUBMIT_KEY__", cfg.submitKey,
		"__SUCCESS_TITLE_KEY__", cfg.successTitleKey,
		"__SUCCESS_TEXT_KEY__", cfg.successTextKey,
		"__MODE__", string(mode),
		"__ENDPOINT__", cfg.endpoint,
		"__SHOW_CONFIRM__", showConfirm,
		"__SHOW_ADDRESSES__", showAddresses,
		"__ADDRESS__", html.EscapeString(address),
		"__SOCKS__", html.EscapeString(socksAddress),
		"__SETUP_I18N__", setupI18nJSON,
	).Replace(setupPage)
}

func writeSetupJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeSetupError(w http.ResponseWriter, status int, code, detail string) {
	err := map[string]string{"code": code}
	if detail != "" {
		err["detail"] = detail
	}
	writeSetupJSON(w, status, err)
}

//go:embed setup_i18n.json
var setupI18nJSON string

const setupPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 64 64%22%3E %3Cdefs%3E %3ClinearGradient id=%22g%22 x1=%220%22 y1=%220%22 x2=%221%22 y2=%221%22%3E %3Cstop offset=%220%22 stop-color=%22#4562e3%22/%3E %3Cstop offset=%221%22 stop-color=%22#22b8cf%22/%3E %3C/linearGradient%3E %3C/defs%3E %3Crect width=%2264%22 height=%2264%22 rx=%2214%22 fill=%22url(#g)%22/%3E %3Cg fill=%22none%22 stroke=%22#fff%22 stroke-width=%224%22 stroke-linecap=%22round%22 stroke-linejoin=%22round%22%3E %3Ccircle cx=%2232%22 cy=%2229%22 r=%2215%22/%3E %3Cellipse cx=%2232%22 cy=%2229%22 rx=%226.5%22 ry=%2215%22/%3E %3Cpath d=%22M17 29h30%22/%3E %3Cpath d=%22M32 44v8M24 52h16%22/%3E %3C/g%3E %3C/svg%3E">
<title>Go Smart Proxy</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f6f7fb; --card: #ffffff; --border: #e3e6ee; --text: #14161f; --muted: #666d80;
    --input: #ffffff; --accent: #4562e3; --accent-h: #3b57cc; --ring: #4562e333; --err: #d1334a;
    --glow1: #627dff26; --glow2: #20c99716; --code: #eef0f6;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #101116; --card: #1a1b22; --border: #2c2e39; --text: #eceef5; --muted: #9096a8;
      --input: #14151b; --accent: #627dff; --accent-h: #788fff; --ring: #627dff44; --err: #ff7a8c;
      --glow1: #627dff30; --glow2: #20c99718; --code: #23252f;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px;
    font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI Variable", "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased; letter-spacing: -0.003em;
    background: radial-gradient(900px 480px at 10% -8%, var(--glow1), transparent),
                radial-gradient(800px 420px at 100% 100%, var(--glow2), transparent), var(--bg);
    color: var(--text);
  }
  .card {
    width: 100%; max-width: 480px; background: var(--card); border: 1px solid var(--border);
    border-radius: 20px; padding: 36px; box-shadow: 0 1px 2px #1018280d, 0 24px 60px -20px #10182833;
  }
  .brand { display: flex; align-items: center; gap: 10px; }
  .mark {
    width: 34px; height: 34px; border-radius: 10px; display: grid; place-items: center; color: #fff;
    background: linear-gradient(135deg, #627dff, #15aabf);
  }
  .mark svg { width: 20px; height: 20px; }
  .logo { font-size: 15px; font-weight: 700; letter-spacing: -.01em; }
  h1 { font-size: 24px; line-height: 1.25; letter-spacing: -.02em; margin: 26px 0 8px; font-weight: 650; }
  p { color: var(--muted); line-height: 1.6; font-size: 14.5px; margin: 0; }
  label { display: block; margin: 20px 0 7px; font-weight: 600; font-size: 13.5px; }
  input {
    width: 100%; padding: 12px 14px; border-radius: 12px; border: 1px solid var(--border);
    background: var(--input); color: var(--text); font-size: 15px; outline: none; font-family: inherit;
    transition: border-color .15s, box-shadow .15s;
  }
  input:focus { border-color: var(--accent); box-shadow: 0 0 0 4px var(--ring); }
  .hint { font-size: 12.5px; color: var(--muted); margin-top: 7px; }
  button {
    width: 100%; margin-top: 26px; padding: 13px 16px; border: 0; border-radius: 12px; font-family: inherit;
    background: var(--accent); color: #fff; font-size: 15px; font-weight: 650; cursor: pointer;
    box-shadow: 0 1px 2px #1018281f; transition: background .15s, transform .08s;
  }
  button:hover { background: var(--accent-h); }
  button:active { transform: translateY(1px); }
  button:focus-visible { outline: none; box-shadow: 0 0 0 4px var(--ring); }
  button:disabled { opacity: .6; cursor: wait; }
  .error { margin-top: 14px; color: var(--err); font-size: 13.5px; min-height: 20px; }
  .ok { display: none; text-align: center; }
  .ok .check {
    width: 56px; height: 56px; margin: 0 auto; border-radius: 50%; display: grid; place-items: center;
    font-size: 28px; color: #12b886; background: #12b88620;
  }
  .ok h1 { margin-top: 20px; }
  .code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px;
    background: var(--code); border-radius: 6px; padding: 2px 7px;
  }
  .addresses { margin-top: 20px; line-height: 2.1; font-size: 14px; color: var(--muted); }
  @media (max-width: 480px) { .card { padding: 26px 22px; border-radius: 16px; } }
</style>
</head>
<body>
  <div class="card">
    <div id="form">
      <div class="brand">
        <div class="mark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3M12 12V8"/></svg></div>
        <div class="logo">Go Smart Proxy</div>
      </div>
      <h1 data-i18n="__TITLE_KEY__">Choose the master password</h1>
      <p data-i18n="__INTRO_KEY__">
        It protects credentials, certificates and relay keys. The configuration will be saved encrypted in
        <span class="code">config.yml.enc</span>. It cannot be recovered.
      </p>
      <form id="setup-form">
        <label for="password" data-i18n="__PASSWORD_LABEL_KEY__">Master password</label>
        <input id="password" type="password" autocomplete="new-password" minlength="8" required autofocus>
        <div class="hint" id="hint" data-i18n="__HINT_KEY__">At least 8 characters. Use a long password and keep it safe.</div>
        <label for="confirm" id="confirm-label" data-i18n="__CONFIRM_LABEL_KEY__">Repeat the master password</label>
        <input id="confirm" type="password" autocomplete="new-password" minlength="8" required>
        <button id="submit" type="submit" data-i18n="__SUBMIT_KEY__">Create configuration</button>
        <div class="error" id="error"></div>
      </form>
    </div>
    <div class="ok" id="ok">
      <div class="check">✓</div>
      <h1 data-i18n="__SUCCESS_TITLE_KEY__">All set</h1>
      <p data-i18n="__SUCCESS_TEXT_KEY__">The encrypted configuration has been created. Opening the interface…</p>
      <div class="addresses" id="addresses">
        <span data-i18n="proxy_label">Proxy HTTP / UI:</span> <span class="code">__ADDRESS__</span><br>
        <span data-i18n="socks_label">SOCKS5 proxy:</span> <span class="code">__SOCKS__</span>
      </div>
    </div>
  </div>
<script>
  const setupI18n = __SETUP_I18N__;
  const mode = '__MODE__';
  const endpoint = '__ENDPOINT__';
  const showConfirm = __SHOW_CONFIRM__;
  const showAddresses = __SHOW_ADDRESSES__;
  const keys = {
    documentTitle: '__DOC_TITLE_KEY__',
    title: '__TITLE_KEY__',
    intro: '__INTRO_KEY__',
    passwordLabel: '__PASSWORD_LABEL_KEY__',
    confirmLabel: '__CONFIRM_LABEL_KEY__',
    hint: '__HINT_KEY__',
    submit: '__SUBMIT_KEY__',
    successTitle: '__SUCCESS_TITLE_KEY__',
    successText: '__SUCCESS_TEXT_KEY__'
  };
  const lang = (localStorage.getItem('gsp.language') || navigator.language || 'en').toLowerCase().split('-')[0];
  const t = (key) => (setupI18n[lang] && setupI18n[lang][key]) || setupI18n.en[key] || key;
  function applyI18n() {
    document.documentElement.lang = lang;
    document.title = t(keys.documentTitle);
    for (const el of document.querySelectorAll('[data-i18n]')) el.textContent = t(el.getAttribute('data-i18n'));
  }
  applyI18n();

  if (!showConfirm) {
    document.getElementById('confirm').style.display = 'none';
    document.getElementById('confirm').required = false;
    document.getElementById('confirm-label').style.display = 'none';
    document.getElementById('hint').style.display = 'none';
  }
  if (!showAddresses) document.getElementById('addresses').style.display = 'none';

  const token = new URLSearchParams(location.search).get('token') || '';
  const form = document.getElementById('setup-form');
  const err = document.getElementById('error');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.textContent = '';
    const password = document.getElementById('password').value;
    const confirm = showConfirm ? document.getElementById('confirm').value : '';
    if (showConfirm) {
      if (password.length < 8) { err.textContent = t('error_short'); return; }
      if (password !== confirm) { err.textContent = t('error_mismatch'); return; }
    } else if (!password) {
      err.textContent = t('error_generic') + '400';
      return;
    }
    const btn = document.getElementById('submit');
    btn.disabled = true;
    try {
      const res = await fetch(endpoint + '?token=' + encodeURIComponent(token), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password, confirm })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        if (data.code === 'too_short') err.textContent = t('error_short');
        else if (data.code === 'mismatch') err.textContent = t('error_mismatch');
        else if (data.code === 'wrong_password') err.textContent = t('unlock_error_wrong');
        else err.textContent = t('error_generic') + (data.detail || data.code || res.status);
        btn.disabled = false;
        return;
      }
      document.getElementById('form').style.display = 'none';
      document.getElementById('ok').style.display = 'block';
      applyI18n();
      setTimeout(() => location.replace('/'), 1800);
    } catch (e) {
      err.textContent = t('error_generic') + e;
      btn.disabled = false;
    }
  });
</script>
</body>
</html>`
