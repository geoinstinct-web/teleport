/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package app

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/httplib"
)

const metaRedirectHTML = `
<!DOCTYPE html>
<html lang="en">
	<head>
		<title>Teleport Redirection Service</title>
		<meta http-equiv="cache-control" content="no-cache"/>
		<meta http-equiv="refresh" content="0;URL='{{.}}'" />
	</head>
	<body></body>
</html>
`

var metaRedirectTemplate = template.Must(template.New("meta-redirect").Parse(metaRedirectHTML))

func SetRedirectPageHeaders(h http.Header, nonce string) {
	httplib.SetNoCacheHeaders(h)
	httplib.SetDefaultSecurityHeaders(h)

	// Set content security policy flags
	scriptSrc := "none"
	if nonce != "" {
		// Should match the <script> tab nonce (random value).
		scriptSrc = fmt.Sprintf("nonce-%v", nonce)
	}
	httplib.SetRedirectPageContentSecurityPolicy(h, scriptSrc)
}

// MetaRedirect issues a "meta refresh" redirect.
func MetaRedirect(w http.ResponseWriter, redirectURL string) error {
	SetRedirectPageHeaders(w.Header(), "")
	return trace.Wrap(metaRedirectTemplate.Execute(w, redirectURL))
}

const js = `
<!DOCTYPE html>
<html lang="en">
  <head>
    <title>Teleport Redirection Service</title>
    <script nonce="%v">
      (function() {
        var url = new URL(window.location);
        var params = new URLSearchParams(url.search);
        var searchParts = window.location.search.split('=');
        var stateValue = params.get("state");
        var subjectValue = params.get("subject");
        var path = params.get("path");
        if (!stateValue) {
          return;
        }
        var hashParts = window.location.hash.split('=');
        if (hashParts.length !== 2 || hashParts[0] !== '#value') {
          return;
        }
        const data = {
          state_value: stateValue,
          cookie_value: hashParts[1],
          subject_cookie_value: subjectValue,
        };
        fetch('/x-teleport-auth', {
          method: 'POST',
          mode: 'same-origin',
          cache: 'no-store',
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
          },
          body: JSON.stringify(data),
        }).then(response => {
          if (response.ok) {
            try {
              // if a path parameter was passed through the redirect, append that path to the target url
              if (path) {
                var redirectUrl = new URL(path, url.origin)
                window.location.replace(redirectUrl.toString());
              } else {
                window.location.replace(url.origin);
              }
            } catch (error) {
                // in case of malformed url, return to origin
                window.location.replace(url.origin)
            }
          }
        });
      })();
    </script>
  </head>
  <body></body>
</html>
`
