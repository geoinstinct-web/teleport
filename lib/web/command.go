/*

 Copyright 2023 Gravitational, Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.


*/

package web

import (
	"net/http"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	"github.com/gravitational/teleport/lib/reversetunnel"
)

func (h *Handler) executeCommand(
	w http.ResponseWriter,
	r *http.Request,
	_ httprouter.Params,
	sessionCtx *SessionContext,
	site reversetunnel.RemoteSite,
) (any, error) {
	return nil, trace.NotImplemented("not implemented")
}
