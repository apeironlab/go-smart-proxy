package main

import (
	"crypto/rand"
	"crypto/subtle"
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
		Handler:           setupHandler(token, addr, socks, finish),
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
	log.Printf("FIRST RUN: open %s to choose the master password", url)
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

// setupHandler serves the first-run page and creates the encrypted config.
func setupHandler(token, address, socksAddress string, done func()) http.Handler {
	mux := http.NewServeMux()

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
		page := strings.ReplaceAll(setupPage, "__ADDRESS__", html.EscapeString(address))
		page = strings.ReplaceAll(page, "__SOCKS__", html.EscapeString(socksAddress))
		fmt.Fprint(w, page)
	})

	var mu sync.Mutex
	created := false
	mux.HandleFunc("POST /api/setup", func(w http.ResponseWriter, r *http.Request) {
		if !validToken(r) {
			writeSetupError(w, http.StatusForbidden, "token di setup non valido")
			return
		}
		var body struct {
			Password string `json:"password"`
			Confirm  string `json:"confirm"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
			writeSetupError(w, http.StatusBadRequest, "richiesta non valida")
			return
		}
		if len(body.Password) < minPasswordLen {
			writeSetupError(w, http.StatusBadRequest, fmt.Sprintf("la master password deve avere almeno %d caratteri", minPasswordLen))
			return
		}
		if body.Password != body.Confirm {
			writeSetupError(w, http.StatusBadRequest, "le due password non coincidono")
			return
		}

		mu.Lock()
		if created {
			mu.Unlock()
			writeSetupError(w, http.StatusConflict, "configurazione già creata")
			return
		}
		if err := createInitialConfig(body.Password, address, socksAddress); err != nil {
			mu.Unlock()
			log.Printf("setup: cannot create the configuration: %v", err)
			writeSetupError(w, http.StatusInternalServerError, "impossibile creare la configurazione")
			return
		}
		created = true
		mu.Unlock()

		writeSetupJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"address": address,
			"socks":   socksAddress,
		})
		go func() {
			time.Sleep(700 * time.Millisecond)
			done()
		}()
	})

	return mux
}

func writeSetupJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeSetupError(w http.ResponseWriter, status int, msg string) {
	writeSetupJSON(w, status, map[string]string{"error": msg})
}

const setupPage = `<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Go Smart Proxy — Primo avvio</title>
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
      <h1>Scegli la master password</h1>
      <p>
        Protegge credenziali, certificati e chiavi del relay. La configurazione verrà salvata
        cifrata in <span class="code">config.yml.enc</span>. Non può essere recuperata.
      </p>
      <form id="setup-form">
        <label for="password">Master password</label>
        <input id="password" type="password" autocomplete="new-password" minlength="8" required autofocus>
        <div class="hint">Almeno 8 caratteri. Usa una password lunga e conservala al sicuro.</div>
        <label for="confirm">Ripeti la master password</label>
        <input id="confirm" type="password" autocomplete="new-password" minlength="8" required>
        <button id="submit" type="submit">Crea la configurazione</button>
        <div class="error" id="error"></div>
      </form>
    </div>
    <div class="ok" id="ok">
      <div class="check">✓</div>
      <h1>Tutto pronto</h1>
      <p>La configurazione cifrata è stata creata. Sto aprendo l'interfaccia…</p>
      <div class="addresses">
        Proxy HTTP / UI: <span class="code">__ADDRESS__</span><br>
        Proxy SOCKS5: <span class="code">__SOCKS__</span>
      </div>
    </div>
  </div>
<script>
  const token = new URLSearchParams(location.search).get('token') || '';
  const form = document.getElementById('setup-form');
  const err = document.getElementById('error');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.textContent = '';
    const password = document.getElementById('password').value;
    const confirm = document.getElementById('confirm').value;
    if (password.length < 8) { err.textContent = 'La master password deve avere almeno 8 caratteri.'; return; }
    if (password !== confirm) { err.textContent = 'Le due password non coincidono.'; return; }
    const btn = document.getElementById('submit');
    btn.disabled = true;
    try {
      const res = await fetch('/api/setup?token=' + encodeURIComponent(token), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password, confirm })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { err.textContent = data.error || ('Errore ' + res.status); btn.disabled = false; return; }
      document.getElementById('form').style.display = 'none';
      document.getElementById('ok').style.display = 'block';
      setTimeout(() => location.replace('/'), 1800);
    } catch (e) {
      err.textContent = 'Impossibile completare il setup: ' + e;
      btn.disabled = false;
    }
  });
</script>
</body>
</html>`
