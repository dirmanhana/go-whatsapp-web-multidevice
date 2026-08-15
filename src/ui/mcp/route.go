package mcp

import (
	"context"
	"net/http"
	"strings"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/infrastructure/whatsapp"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/ui/rest/middleware"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/mark3labs/mcp-go/server"
	"github.com/sirupsen/logrus"
)

// Register mounts the MCP streamable-HTTP endpoint at /mcp on the given
// router (which already carries AppBasePath and the auth middleware).
//
// Device scoping mirrors REST: the X-Device-Id header picks the device for
// the connection (empty resolves the default device, same as
// DeviceMiddleware); a per-call device_id tool argument overrides it (see
// resolveDeviceContext).
//
// auth is optional; when config.AuthEnabled it is used to authenticate the
// Bearer token so device resolution is scoped to the connection's user.
func Register(router fiber.Router, dm *whatsapp.DeviceManager, deps Deps, auth ...middleware.TokenAuthenticator) {
	// dm is typed here, but handlers take the deviceResolver interface;
	// a nil *DeviceManager must become a nil interface, not a typed nil.
	var resolver deviceResolver
	if dm != nil {
		resolver = dm
	}

	var authService middleware.TokenAuthenticator
	if len(auth) > 0 {
		authService = auth[0]
	}

	httpServer := server.NewStreamableHTTPServer(
		NewServer(deps, resolver),
		// Stateless: no server-initiated notifications or subscriptions are
		// used, and it avoids tying a session store to Fiber's shutdown.
		server.WithStateLess(true),
		// No server-initiated notifications are used, so the standalone GET
		// SSE stream is never needed. Without this, a GET reaches mcp-go's
		// "for { select { case <-writeChan: ...; case <-ctx.Done(): } }"
		// loop; ctx there is the *fasthttp.RequestCtx, whose Done() channel
		// only closes on server shutdown (not client disconnect), so the
		// goroutine, the fasthttp body-stream writer, and the connection/FD
		// would all be pinned forever through the fasthttp adaptor.
		server.WithDisableStreaming(true),
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			if dm == nil {
				return ctx
			}
			deviceID := strings.TrimSpace(r.Header.Get(middleware.DeviceIDHeader))

			if config.AuthEnabled {
				// Multi-user mode: authenticate the Bearer token and scope
				// device resolution to that user. An unauthenticated request
				// gets no device context, so tools surface "device
				// identification required" instead of reaching another user's
				// devices.
				if authService == nil {
					return ctx
				}
				user, err := authenticateMCPUser(ctx, authService, r.Header.Get("Authorization"))
				if err != nil || user == nil {
					logrus.Debugf("MCP auth failed for device %q: %v", deviceID, err)
					return ctx
				}
				ctx = domainChatStorage.ContextWithUser(ctx, user)
				inst, _, err := dm.ResolveDeviceForUser(user.ID, deviceID)
				if err != nil {
					logrus.Debugf("MCP device resolution failed for %q: %v", deviceID, err)
					return ctx
				}
				return whatsapp.ContextWithDevice(ctx, inst)
			}

			inst, _, err := dm.ResolveDevice(deviceID)
			if err != nil {
				// Leave the context empty; handlers surface a tool error
				// ("device identification required") on use.
				logrus.Debugf("MCP device resolution failed for %q: %v", deviceID, err)
				return ctx
			}
			return whatsapp.ContextWithDevice(ctx, inst)
		}),
	)

	handler := adaptor.HTTPHandler(httpServer)
	// POST carries JSON-RPC calls; DELETE is part of the streamable-HTTP
	// session lifecycle. GET is intentionally not mounted: with streaming
	// disabled mcp-go would just 405 it, so Fiber's own 404 for an
	// unmounted method is equivalent and keeps the route surface narrow.
	router.Post("/mcp", handler)
	router.Delete("/mcp", handler)
}

// authenticateMCPUser resolves the request's identity like the REST
// AuthMiddleware: a Bearer token first, then Basic credentials, so both
// programmatic MCP clients and dashboard-style Basic auth work identically
// on every surface. A nil auth service or missing/empty credentials yields
// a nil user without error (the caller decides how to react).
func authenticateMCPUser(ctx context.Context, auth middleware.TokenAuthenticator, authorization string) (*domainChatStorage.User, error) {
	if auth == nil {
		return nil, nil
	}
	if token := middleware.BearerToken(authorization); token != "" {
		return auth.Authenticate(ctx, token)
	}
	if basic, ok := auth.(middleware.BasicAuthenticator); ok {
		username, password := middleware.BasicCredentials(authorization)
		if username != "" {
			return basic.AuthenticateBasic(ctx, username, password)
		}
	}
	return nil, nil
}
