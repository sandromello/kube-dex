package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/sirupsen/logrus"
)

var (
	logLevels  = []string{"debug", "info", "error"}
	logFormats = []string{"json", "text"}
)

// TODO: fix it, state must be random
const exampleAppState = "my-test-state"

type Claims struct {
	Name   string   `json:"name"`
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

type Handler struct {
	cfg      *Config
	client   *http.Client
	logger   logrus.FieldLogger
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	tmpl     *template.Template
}

func NewHandler(
	cfg *Config,
	client *http.Client,
	provider *oidc.Provider,
	verifier *oidc.IDTokenVerifier,
	tmpl *template.Template,
	logger logrus.FieldLogger,
) *Handler {
	return &Handler{
		cfg:      cfg,
		client:   client,
		provider: provider,
		verifier: verifier,
		tmpl:     tmpl,
		logger:   logger,
	}
}

// Callback exchanges a token for the received code and then redirect to index
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, fmt.Sprintf("Method not implemented: %s", r.Method), http.StatusMethodNotAllowed)
	}
	if errMsg := r.FormValue("error"); errMsg != "" {
		http.Error(w, errMsg+": "+r.FormValue("error_description"), http.StatusBadRequest)
		return
	}

	ctx := oidc.ClientContext(r.Context(), h.client)
	oauth2Config := h.cfg.Oauth2Config(h.provider.Endpoint(), nil)

	// Authorization redirect callback from OAuth2 auth flow.
	if errMsg := r.FormValue("error"); errMsg != "" {
		http.Error(w, errMsg+": "+r.FormValue("error_description"), http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
		return
	}
	if state := r.FormValue("state"); state != exampleAppState {
		http.Error(w, fmt.Sprintf("expected state %q got %q", exampleAppState, state), http.StatusBadRequest)
		return
	}
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}
	redirectToIndex := fmt.Sprintf("%s?id_token=%s", h.cfg.Listen, rawIDToken)
	http.Redirect(w, r, redirectToIndex, http.StatusSeeOther)
}

func (h *Handler) Index(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, fmt.Sprintf("Method not implemented: %s", r.Method), http.StatusMethodNotAllowed)
	}
	qs := r.URL.Query()
	rawIDToken := qs.Get("id_token")
	if rawIDToken == "" {
		authCodeURL := h.cfg.Oauth2Config(
			h.provider.Endpoint(),
			h.cfg.GetScopes(),
		).AuthCodeURL(exampleAppState)
		http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
		return
	}
	idToken, err := h.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to verify ID token: %v", err), http.StatusInternalServerError)
		return
	}
	idTokenInfo := ""
	if qs.Get("tokenInfo") == "1" {
		var jClaims json.RawMessage
		idToken.Claims(&jClaims)
		buff := new(bytes.Buffer)
		json.Indent(buff, []byte(jClaims), "", "  ")
		idTokenInfo = string(buff.Bytes())
	}
	var claims Claims
	idToken.Claims(&claims)
	kubeConfigURL := template.JS(fmt.Sprintf(
		"kubeconfig.yaml?email=%s&id_token=%s",
		claims.Email,
		rawIDToken,
	))
	showPublicK8sRootCA := false
	if h.cfg.PublicK8sAPIServerRootCA != "" {
		showPublicK8sRootCA = true
	}

	timeToExpire := time.Since(idToken.Expiry).Round(time.Second) * -1
	data := map[string]interface{}{
		"title":                    "My Web Page",
		"IDToken":                  rawIDToken,
		"IDTokenInfo":              idTokenInfo,
		"PublicK8sAPIServer":       h.cfg.PublicK8sAPIServer,
		"PublicK8sAPIServerRootCA": showPublicK8sRootCA,
		"ClusterName":              h.cfg.ClusterName,
		"Email":                    claims.Email,
		"Name":                     claims.Name,
		"Groups":                   claims.Groups,
		"KubeConfigURL":            kubeConfigURL,
		"ExpireAt":                 idToken.Expiry.Format(time.RFC822Z),
		"TimeToExpire":             fmt.Sprintf("%v to expire", timeToExpire),
	}
	h.tmpl.ExecuteTemplate(w, "index.html", data)
}

func (h *Handler) K8sRootCA(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", r.Header.Get("Content-Type"))
	w.Header().Set(
		"Content-Disposition",
		fmt.Sprintf("attachment; filename=%s-ca.crt", h.cfg.ClusterName),
	)
	w.Write([]byte(h.cfg.PublicK8sAPIServerRootCA))
}

func (h *Handler) KubeConfig(w http.ResponseWriter, r *http.Request) {
	qs := r.URL.Query()
	kubeConfigCa := base64.StdEncoding.EncodeToString([]byte(h.cfg.PublicK8sAPIServerRootCA))
	data := map[string]interface{}{
		"IDToken":                  qs.Get("id_token"),
		"PublicK8sAPIServer":       h.cfg.PublicK8sAPIServer,
		"PublicK8sAPIServerRootCA": kubeConfigCa,
		"ClusterName":              h.cfg.ClusterName,
		"Email":                    qs.Get("email"),
	}
	email := strings.Split(qs.Get("email"), "@")[0]
	if email == "" {
		email = "kubeconfig"
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set(
		"Content-Disposition",
		fmt.Sprintf("attachment; filename=%s.yaml", email),
	)
	h.tmpl.ExecuteTemplate(w, "kubeconfig.yaml", data)
}

type utcFormatter struct {
	f logrus.Formatter
}

func (f *utcFormatter) Format(e *logrus.Entry) ([]byte, error) {
	e.Time = e.Time.UTC()
	return f.f.Format(e)
}

func NewLogger(level string, format string) (logrus.FieldLogger, error) {
	var logLevel logrus.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = logrus.DebugLevel
	case "", "info":
		logLevel = logrus.InfoLevel
	case "error":
		logLevel = logrus.ErrorLevel
	default:
		return nil, fmt.Errorf("log level is not one of the supported values (%s): %s", strings.Join(logLevels, ", "), level)
	}

	var formatter utcFormatter
	switch strings.ToLower(format) {
	case "", "text":
		formatter.f = &logrus.TextFormatter{DisableColors: true}
	case "json":
		formatter.f = &logrus.JSONFormatter{}
	default:
		return nil, fmt.Errorf("log format is not one of the supported values (%s): %s", strings.Join(logFormats, ", "), format)
	}

	return &logrus.Logger{
		Out:       os.Stderr,
		Formatter: &formatter,
		Level:     logLevel,
	}, nil
}
