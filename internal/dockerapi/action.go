// Package dockerapi classifies raw Docker Engine API HTTP requests into
// canonical, policy-friendly action names such as "container.create" or
// "image.pull". The classifier is intentionally read-only and has no
// dependency on the Docker SDK: it only needs the request method and path.
package dockerapi

import (
	"regexp"
	"strings"
)

// Action is the canonical name of a Docker operation, e.g. "container.create".
// The special value ActionUnknown is returned for paths DockGate does not
// recognise; policies should treat unknown actions conservatively (the default
// action, which ships as "deny").
type Action string

const ActionUnknown Action = "unknown"

// Category returns the coarse group of an action ("container", "image", ...).
// For ActionUnknown it returns "unknown".
func (a Action) Category() string {
	s := string(a)
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return s[:i]
	}
	return s
}

// NeedsBodyInspection reports whether evaluating this action may require the
// request body (currently only container creation, whose HostConfig carries
// the security-relevant settings). The gateway uses this to decide when to
// buffer the request body instead of streaming it straight through.
func (a Action) NeedsBodyInspection() bool {
	return a == "container.create"
}

// route binds a method + compiled path pattern to an action.
type route struct {
	method string
	re     *regexp.Regexp
	action Action
}

// apiVersionPrefix strips the optional "/v1.43"-style API version segment that
// Docker clients prepend to every request.
var apiVersionPrefix = regexp.MustCompile(`^/v[0-9]+\.[0-9]+`)

// id matches a container/image/network/volume identifier or name segment.
const id = `[^/]+`

func mustRoute(method, pattern string, action Action) route {
	return route{
		method: method,
		re:     regexp.MustCompile("^" + pattern + "$"),
		action: action,
	}
}

// routes is evaluated in order; the first method+path match wins. More specific
// patterns must precede more general ones.
var routes = []route{
	// System / meta.
	mustRoute("GET", `/_ping`, "system.ping"),
	mustRoute("HEAD", `/_ping`, "system.ping"),
	mustRoute("GET", `/version`, "system.version"),
	mustRoute("GET", `/info`, "system.info"),
	mustRoute("GET", `/events`, "system.events"),
	mustRoute("GET", `/system/df`, "system.df"),
	mustRoute("POST", `/auth`, "system.auth"),

	// Containers — specific verbs before the generic inspect/remove routes.
	mustRoute("GET", `/containers/json`, "container.list"),
	mustRoute("POST", `/containers/create`, "container.create"),
	mustRoute("POST", `/containers/prune`, "container.prune"),
	mustRoute("GET", `/containers/`+id+`/json`, "container.inspect"),
	mustRoute("GET", `/containers/`+id+`/logs`, "container.logs"),
	mustRoute("GET", `/containers/`+id+`/top`, "container.top"),
	mustRoute("GET", `/containers/`+id+`/stats`, "container.stats"),
	mustRoute("GET", `/containers/`+id+`/changes`, "container.changes"),
	mustRoute("GET", `/containers/`+id+`/export`, "container.export"),
	mustRoute("GET", `/containers/`+id+`/archive`, "container.archive.read"),
	mustRoute("HEAD", `/containers/`+id+`/archive`, "container.archive.read"),
	mustRoute("PUT", `/containers/`+id+`/archive`, "container.archive.write"),
	mustRoute("POST", `/containers/`+id+`/start`, "container.start"),
	mustRoute("POST", `/containers/`+id+`/stop`, "container.stop"),
	mustRoute("POST", `/containers/`+id+`/restart`, "container.restart"),
	mustRoute("POST", `/containers/`+id+`/kill`, "container.kill"),
	mustRoute("POST", `/containers/`+id+`/pause`, "container.pause"),
	mustRoute("POST", `/containers/`+id+`/unpause`, "container.unpause"),
	mustRoute("POST", `/containers/`+id+`/rename`, "container.rename"),
	mustRoute("POST", `/containers/`+id+`/update`, "container.update"),
	mustRoute("POST", `/containers/`+id+`/resize`, "container.resize"),
	mustRoute("POST", `/containers/`+id+`/wait`, "container.wait"),
	mustRoute("POST", `/containers/`+id+`/attach`, "container.attach"),
	mustRoute("POST", `/containers/`+id+`/exec`, "container.exec"),
	mustRoute("DELETE", `/containers/`+id, "container.remove"),

	// Exec lifecycle (the exec instance is created via container.exec above).
	mustRoute("POST", `/exec/`+id+`/start`, "exec.start"),
	mustRoute("POST", `/exec/`+id+`/resize`, "exec.resize"),
	mustRoute("GET", `/exec/`+id+`/json`, "exec.inspect"),

	// Images.
	mustRoute("GET", `/images/json`, "image.list"),
	mustRoute("POST", `/images/create`, "image.pull"),
	mustRoute("POST", `/images/prune`, "image.prune"),
	mustRoute("POST", `/images/load`, "image.load"),
	mustRoute("GET", `/images/search`, "image.search"),
	mustRoute("GET", `/images/`+id+`/json`, "image.inspect"),
	mustRoute("GET", `/images/`+id+`/history`, "image.history"),
	mustRoute("GET", `/images/`+id+`/get`, "image.save"),
	mustRoute("POST", `/images/`+id+`/tag`, "image.tag"),
	mustRoute("POST", `/images/`+id+`/push`, "image.push"),
	mustRoute("DELETE", `/images/`+id, "image.remove"),
	mustRoute("POST", `/build`, "image.build"),
	mustRoute("POST", `/commit`, "image.commit"),

	// Networks.
	mustRoute("GET", `/networks`, "network.list"),
	mustRoute("POST", `/networks/create`, "network.create"),
	mustRoute("POST", `/networks/prune`, "network.prune"),
	mustRoute("GET", `/networks/`+id, "network.inspect"),
	mustRoute("POST", `/networks/`+id+`/connect`, "network.connect"),
	mustRoute("POST", `/networks/`+id+`/disconnect`, "network.disconnect"),
	mustRoute("DELETE", `/networks/`+id, "network.remove"),

	// Volumes.
	mustRoute("GET", `/volumes`, "volume.list"),
	mustRoute("POST", `/volumes/create`, "volume.create"),
	mustRoute("POST", `/volumes/prune`, "volume.prune"),
	mustRoute("GET", `/volumes/`+id, "volume.inspect"),
	mustRoute("DELETE", `/volumes/`+id, "volume.remove"),

	// Swarm / services / secrets / configs (grouped; usually denied for agents).
	mustRoute("POST", `/swarm/init`, "swarm.init"),
	mustRoute("POST", `/swarm/join`, "swarm.join"),
	mustRoute("POST", `/swarm/leave`, "swarm.leave"),
	mustRoute("GET", `/swarm`, "swarm.inspect"),
	mustRoute("GET", `/services`, "service.list"),
	mustRoute("POST", `/services/create`, "service.create"),
	mustRoute("GET", `/secrets`, "secret.list"),
	mustRoute("POST", `/secrets/create`, "secret.create"),
	mustRoute("GET", `/configs`, "config.list"),
	mustRoute("POST", `/configs/create`, "config.create"),
}

// Classify maps an HTTP method and request path to a canonical Action.
// The path may include the optional Docker API version prefix and a query
// string; both are handled. Unrecognised requests return ActionUnknown.
func Classify(method, path string) Action {
	method = strings.ToUpper(method)

	// Drop any query string.
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	// Strip the optional API version prefix ("/v1.43").
	path = apiVersionPrefix.ReplaceAllString(path, "")
	// Normalise a trailing slash (but keep the root "/").
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	if path == "" {
		path = "/"
	}

	for _, r := range routes {
		if r.method == method && r.re.MatchString(path) {
			return r.action
		}
	}
	return ActionUnknown
}
