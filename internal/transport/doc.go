// Package transport owns the shared wush network lifecycle.
//
// It composes the encrypted DERP control overlay, the in-memory control server,
// and an ephemeral tsnet node into client and host transports. CLI commands
// build application behavior on top of its Dial, Listen, HTTP, direct-path,
// and session-scoped UDP listener APIs.
package transport
