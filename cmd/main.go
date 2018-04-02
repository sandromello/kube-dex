package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/sandromello/kube-dex/pkg/server"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var cfg server.Config
var rootDir, _ = os.Getwd()

// return an HTTP client which trusts the provided root CAs.
func httpClientForRootCAs(rootCAs string) (*http.Client, error) {
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
	rootCABytes, err := ioutil.ReadFile(rootCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to read root-ca: %v", err)
	}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
		return nil, fmt.Errorf("no certs found in root CA file %q", rootCAs)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

func cmd() *cobra.Command {
	c := cobra.Command{
		Use:   "kube-dex",
		Short: "An OpenID Connect client for Koli",
		Long:  "",
		RunE: func(cmd *cobra.Command, args []string) error {
			staticDir := path.Join("", "web/static")
			fs := http.FileServer(http.Dir(staticDir))
			http.Handle("/static/", http.StripPrefix("/static/", fs))

			logger, err := server.NewLogger(logrus.InfoLevel.String(), "text")
			if err != nil {
				return fmt.Errorf("invalid config: %v", err)
			}

			var client *http.Client
			if cfg.RootCAs != "" {
				client, err = httpClientForRootCAs(cfg.RootCAs)
				if err != nil {
					return err
				}
			}
			if client == nil {
				client = http.DefaultClient
			}

			if cfg.PublicK8sAPIServerRootCA != "" {
				cfg.LoadPublicK8sAPIServerRootCA()
			}

			ctx := oidc.ClientContext(context.Background(), client)
			provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
			if err != nil {
				return fmt.Errorf("Failed to query provider %q: %v", cfg.IssuerURL, err)
			}
			verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
			// Load templates
			lp := filepath.Join("", "web/templates", "index.html")
			kc := filepath.Join("", "web/templates", "kubeconfig.yaml")
			tmpl, err := template.New("").ParseFiles(lp, kc)
			if err != nil {
				log.Fatalf("Failed parsing templates: %v", err)
			}

			handler := server.NewHandler(&cfg, client, provider, verifier, tmpl, logger)
			http.HandleFunc("/", handler.Index)
			http.HandleFunc("/ca.crt", handler.K8sRootCA)
			http.HandleFunc("/callback", handler.Callback)
			http.HandleFunc("/kubeconfig.yaml", handler.KubeConfig)

			log.Println("Starting kube-dex server at :5555 ...")
			return http.ListenAndServe(":5555", nil)
		},
	}
	c.Flags().StringVar(&cfg.ClusterName, "cluster-name", "", "The name of the cluster.")
	c.Flags().StringVar(&cfg.PublicK8sAPIServer, "public-api-server", "", "The public Kubernetes API server address.")
	c.Flags().StringVar(&cfg.PublicK8sAPIServerRootCA, "public-api-server-ca", "", "The public Kubernetes API server root certificate authorities")
	c.Flags().StringVar(&cfg.APIServer, "api-server", "", "Kubernetes API server address, e.g. 'http://127.0.0.1:8080'. Omit parameter to run in on-cluster mode and utilize the service account token.")
	c.Flags().StringVar(&cfg.ClientID, "client-id", "example-app", "OAuth2 client ID of this application.")
	c.Flags().StringVar(&cfg.ClientSecret, "client-secret", "ZXhhbXBsZS1hcHAtc2VjcmV0", "OAuth2 client secret of this application.")
	c.Flags().StringVar(&cfg.IssuerURL, "issuer", "http://127.0.0.1:5556/dex", "URL of the OpenID Connect issuer.")
	c.Flags().StringVar(&cfg.Listen, "listen", "http://127.0.0.1:5555", "HTTP(S) address to listen at.")
	c.Flags().StringVar(&cfg.RedirectURI, "redirect-uri", "http://127.0.0.1:5555/callback", "Callback URL for OAuth2 responses.")
	c.Flags().StringVar(&cfg.RootCAs, "issuer-root-ca", "", "Root certificate authorities for the issuer. Defaults to host certs.")
	c.Flags().StringVar(&cfg.Scopes, "scopes", "openid profile email groups", "The scopes which will be used on requesting the id_token")
	return &c
}

func main() {
	if err := cmd().Execute(); err != nil {
		log.Fatalf("Failed starting app: %v", err)
	}
}
