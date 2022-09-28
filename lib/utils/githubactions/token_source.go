package githubactions

import (
	"context"
	"encoding/json"
	"github.com/gravitational/trace"
	"io"
	"net/http"
	"net/url"
	"os"
)

type tokenResponse struct {
	Value string `json:"value"`
}

// IDTokenSource allows a GitHub ID token to be fetched whilst executing
// within the context of a GitHub actions workflow.
type IDTokenSource struct {
	getIDTokenURL   func() string
	getRequestToken func() string
	client          http.Client
}

func NewIDTokenSource() *IDTokenSource {
	return &IDTokenSource{
		getIDTokenURL: func() string {
			return os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
		},
		getRequestToken: func() string {
			return os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		},
	}
}

// GetIDToken utilises values set in the environment and the GitHub API to
// fetch a GitHub issued IDToken.
func (ip *IDTokenSource) GetIDToken(ctx context.Context) (string, error) {
	audience := "teleport.cluster.local"

	tokenURL := ip.getIDTokenURL()
	requestToken := ip.getRequestToken()
	if tokenURL == "" {
		return "", trace.BadParameter(
			"ACTIONS_ID_TOKEN_REQUEST_URL environment variable missing",
		)
	}
	if requestToken == "" {
		return "", trace.BadParameter(
			"ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable missing",
		)
	}

	tokenURL = tokenURL + "&audience=" + url.QueryEscape(audience)
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, tokenURL, nil,
	)
	if err != nil {
		return "", trace.Wrap(err)
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)
	req.Header.Set("Accept", "application/json; api-version=2.0")
	req.Header.Set("Content-Type", "application/json")
	res, err := ip.client.Do(req)
	if err != nil {
		return "", trace.Wrap(err)
	}
	defer res.Body.Close()

	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", trace.Wrap(err)
	}

	var data tokenResponse
	if err := json.Unmarshal(bytes, &data); err != nil {
		return "", trace.Wrap(err)
	}

	if data.Value == "" {
		return "", trace.Errorf("response did not include ID token")
	}

	return data.Value, nil
}
