package middleware

import (
	"net/url"
	"strings"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/infrastructure/whatsapp"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/utils"
	"github.com/gofiber/fiber/v3"
)

const DeviceIDHeader = "X-Device-Id"

// isDevicesProbePath reports whether the path is the dashboard's auto-connect
// probe (GET /devices, base-path aware).
func isDevicesProbePath(path string) bool {
	return path == "/devices" || path == config.AppBasePath+"/devices"
}

// DeviceMiddleware fetches a device instance by header (preferred), path param, or query param
// and injects it into the context. It falls back to the default/only device for single-device mode.
func DeviceMiddleware(dm *whatsapp.DeviceManager) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Allow non-device-scoped public endpoints (e.g., landing page) to pass through.
		path := strings.TrimSpace(c.Path())
		if path == "/" || path == "" || path == config.AppBasePath || path == config.AppBasePath+"/" {
			return c.Next()
		}

		if dm == nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(utils.ResponseData{
				Status:  fiber.StatusServiceUnavailable,
				Code:    "DEVICE_MANAGER_UNAVAILABLE",
				Message: "Device manager is not initialized",
				Results: nil,
			})
		}

		deviceID := strings.TrimSpace(c.Get(DeviceIDHeader))
		// URL-decode the header value to support non-ASCII characters
		if decoded, err := url.QueryUnescape(deviceID); err == nil {
			deviceID = decoded
		}
		if deviceID == "" {
			deviceID = strings.TrimSpace(c.Query("device_id"))
		}

		// In multi-user mode a device must resolve for the authenticated user
		// (unowned slots are claimed on first use). Without a user, requests
		// are rejected: every device-scoped route sits behind AuthMiddleware.
		// The only exception is the dashboard auto-connect probe: it calls
		// GET /devices with no credentials to discover the server URL, and the
		// handler returns an empty list for unauthenticated callers.
		var instance *whatsapp.DeviceInstance
		var resolvedID string
		var err error
		if user, ok := domainChatStorage.UserFromContext(c.Context()); ok && user != nil {
			instance, resolvedID, err = dm.ResolveDeviceForUser(user.ID, deviceID)
		} else if config.AuthEnabled {
			if c.Method() == fiber.MethodGet && isDevicesProbePath(strings.TrimSpace(c.Path())) {
				return c.Next()
			}
			return unauthorizedResponse(c)
		} else {
			instance, resolvedID, err = dm.ResolveDevice(deviceID)
		}
		if err != nil {
			// ResolveDevice returns an ID when provided but missing; use it for payload clarity.
			if resolvedID != "" || strings.TrimSpace(deviceID) != "" {
				return c.Status(fiber.StatusNotFound).JSON(utils.ResponseData{
					Status:  fiber.StatusNotFound,
					Code:    "DEVICE_NOT_FOUND",
					Message: "device not found; create a device first from /api/devices or provide a valid X-Device-Id",
					Results: map[string]string{"device_id": resolvedID},
				})
			}

			return c.Status(fiber.StatusBadRequest).JSON(utils.ResponseData{
				Status:  fiber.StatusBadRequest,
				Code:    "DEVICE_ID_REQUIRED",
				Message: "device_id is required via X-Device-Id header or device_id query",
				Results: nil,
			})
		}

		c.Locals("device_id", resolvedID)
		c.Locals("device", instance)
		c.SetContext(whatsapp.ContextWithDevice(c.Context(), instance))
		return c.Next()
	}
}
