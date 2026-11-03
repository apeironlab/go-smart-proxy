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
<title>Go Smart Proxy</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: radial-gradient(1200px 600px at 20% -10%, #1f6feb33, transparent),
                radial-gradient(900px 500px at 100% 100%, #2ea04333, transparent), #0d1117;
    color: #e6edf3;
  }
  .card {
    width: 100%; max-width: 520px; background: #161b22; border: 1px solid #30363d;
    border-radius: 16px; padding: 32px; box-shadow: 0 24px 80px #0008;
  }
  .logo { font-size: 13px; letter-spacing: .12em; text-transform: uppercase; color: #8b949e; }
  h1 { font-size: 26px; margin: 8px 0 6px; }
  p { color: #8b949e; line-height: 1.5; }
  label { display: block; margin: 18px 0 6px; font-weight: 600; font-size: 14px; }
  input {
    width: 100%; padding: 12px 14px; border-radius: 10px; border: 1px solid #30363d;
    background: #0d1117; color: #e6edf3; font-size: 16px; outline: none;
  }
  input:focus { border-color: #1f6feb; box-shadow: 0 0 0 3px #1f6feb33; }
  .hint { font-size: 12px; color: #8b949e; margin-top: 6px; }
  button {
    width: 100%; margin-top: 24px; padding: 13px 16px; border: 0; border-radius: 10px;
    background: #238636; color: white; font-size: 16px; font-weight: 700; cursor: pointer;
  }
  button:hover { background: #2ea043; }
  button:disabled { opacity: .6; cursor: wait; }
  .error { margin-top: 16px; color: #ff7b72; font-size: 14px; min-height: 20px; }
  .ok { display: none; text-align: center; }
  .ok .check { font-size: 42px; color: #3fb950; }
  .code { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 2px 6px; }
  .addresses { margin-top: 14px; line-height: 1.9; }
</style>
</head>
<body>
  <div class="card">
    <div id="form">
      <div class="logo">Go Smart Proxy</div>
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
