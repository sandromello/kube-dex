package server

import (
	"io/ioutil"
	"log"
	"strings"

	"golang.org/x/oauth2"
)

// Config defines configuration parameters for dex kubeconfig
type Config struct {
	ClientID                 string
	ClientSecret             string
	RedirectURI              string
	IssuerURL                string
	ClusterName              string
	APIServer                string
	PublicK8sAPIServer       string
	PublicK8sAPIServerRootCA string
	Listen                   string
	RootCAs                  string
	Scopes                   string
}

// GetScopes return then as a slice of strings
func (c *Config) GetScopes() []string {
	return strings.Split(c.Scopes, " ")
}

func (c *Config) Oauth2Config(endpoint oauth2.Endpoint, scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     endpoint,
		Scopes:       scopes,
		RedirectURL:  c.RedirectURI,
	}
}

// LoadPublicK8sAPIServerRootCA load the certificate authority file into memory
func (c *Config) LoadPublicK8sAPIServerRootCA() {
	rootCABytes, err := ioutil.ReadFile(c.PublicK8sAPIServerRootCA)
	if err != nil {
		log.Fatalf("failed to read root-ca: %v", err)
	}
	c.PublicK8sAPIServerRootCA = string(rootCABytes)
}
