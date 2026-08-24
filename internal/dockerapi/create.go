package dockerapi

import (
	"encoding/json"
	"strings"
)

// CreateSpec is the subset of a Docker `POST /containers/create` body that is
// relevant to security policy. Fields DockGate does not evaluate are ignored so
// the struct stays small and forward-compatible with newer API versions.
type CreateSpec struct {
	Image      string
	Privileged bool
	// NetworkMode is the raw HostConfig.NetworkMode string ("host", "bridge",
	// a container: reference, etc.).
	NetworkMode string
	// PidMode is HostConfig.PidMode ("host" shares the host PID namespace).
	PidMode string
	// IpcMode is HostConfig.IpcMode ("host" shares the host IPC namespace).
	IpcMode string
	// BindMounts holds host paths mounted into the container, gathered from both
	// HostConfig.Binds ("hostpath:containerpath") and HostConfig.Mounts of type
	// "bind".
	BindMounts []string
	// CapAdd lists Linux capabilities added to the container (upper-cased,
	// without the "CAP_" prefix, e.g. "SYS_ADMIN").
	CapAdd []string
	// User is the configured user ("" means the image default, typically root).
	User string
}

// rawCreate mirrors the wire format just enough to decode the fields above.
type rawCreate struct {
	Image      string `json:"Image"`
	User       string `json:"User"`
	HostConfig struct {
		Privileged  bool     `json:"Privileged"`
		NetworkMode string   `json:"NetworkMode"`
		PidMode     string   `json:"PidMode"`
		IpcMode     string   `json:"IpcMode"`
		Binds       []string `json:"Binds"`
		CapAdd      []string `json:"CapAdd"`
		Mounts      []struct {
			Type   string `json:"Type"`
			Source string `json:"Source"`
		} `json:"Mounts"`
	} `json:"HostConfig"`
}

// ParseCreateSpec decodes a container-create body into a CreateSpec. A nil or
// empty body yields a zero-value spec and no error. Malformed JSON returns an
// error so the gateway can fail closed rather than silently under-inspect.
func ParseCreateSpec(body []byte) (CreateSpec, error) {
	var spec CreateSpec
	if len(strings.TrimSpace(string(body))) == 0 {
		return spec, nil
	}

	var raw rawCreate
	if err := json.Unmarshal(body, &raw); err != nil {
		return spec, err
	}

	spec.Image = raw.Image
	spec.User = raw.User
	spec.Privileged = raw.HostConfig.Privileged
	spec.NetworkMode = raw.HostConfig.NetworkMode
	spec.PidMode = raw.HostConfig.PidMode
	spec.IpcMode = raw.HostConfig.IpcMode

	// Normalise capabilities to bare, upper-cased names (SYS_ADMIN, not
	// cap_sys_admin) so policy matching is predictable.
	for _, c := range raw.HostConfig.CapAdd {
		c = strings.ToUpper(strings.TrimPrefix(strings.ToUpper(c), "CAP_"))
		if c != "" {
			spec.CapAdd = append(spec.CapAdd, c)
		}
	}

	// Bind mounts from the legacy Binds field ("hostpath:ctrpath[:opts]").
	for _, b := range raw.HostConfig.Binds {
		host := b
		if i := strings.IndexByte(b, ':'); i >= 0 {
			host = b[:i]
		}
		// A named volume (no leading slash) is not a host bind mount.
		if strings.HasPrefix(host, "/") {
			spec.BindMounts = append(spec.BindMounts, host)
		}
	}
	// Bind mounts from the modern Mounts field.
	for _, m := range raw.HostConfig.Mounts {
		if strings.EqualFold(m.Type, "bind") && m.Source != "" {
			spec.BindMounts = append(spec.BindMounts, m.Source)
		}
	}

	return spec, nil
}
