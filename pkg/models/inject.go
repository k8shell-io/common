package models

// InjectNamespaces lists the namespaces a workspace may be injected into.
type InjectNamespaces struct {
	// Namespaces are the namespaces open to injection. Empty means injection
	// is disabled.
	Namespaces []string `json:"namespaces"`
	// ClusterWide is true when the provisioner is configured to allow
	// injection into every namespace ("*"), in which case Namespaces is a
	// live snapshot of the namespaces that currently exist rather than a
	// fixed allow-list.
	ClusterWide bool `json:"clusterWide,omitempty"`
}

// InjectWorkload is a workload a workspace can be injected into, together
// with its current injection state.
type InjectWorkload struct {
	// Namespace is the Kubernetes namespace holding the workload.
	Namespace string `json:"namespace"`
	// Kind is the workload kind: "deployment", "statefulset", or "daemonset".
	Kind string `json:"kind"`
	// Name is the workload name. Together with Kind and Namespace it forms
	// the "workload=<kind>/<name>+ns=<namespace>" part of an inject-mode userstr.
	Name string `json:"name"`
	// Replicas is the workload's desired replica count. Injecting produces
	// one workspace per replica.
	Replicas int32 `json:"replicas"`
	// Injected is true when this workload already hosts an injected
	// workspace. A workload holds at most one, so a caller must treat an
	// injected workload as unavailable until it is ejected.
	Injected bool `json:"injected,omitempty"`
	// Workspace is the canonical id of the workspace currently injected into
	// this workload. Empty unless Injected is true.
	Workspace string `json:"workspace,omitempty"`
	// Username is the owner of the currently injected workspace, and
	// Organization their tenant. Both are empty unless Injected is true.
	Username     string `json:"username,omitempty"`
	Organization string `json:"organization,omitempty"`
	// Blueprint is the blueprint the injected workspace was created from.
	// Empty unless Injected is true.
	Blueprint string `json:"blueprint,omitempty"`
}
