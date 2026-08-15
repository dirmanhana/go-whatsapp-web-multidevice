package websocket

import (
	"context"
	"encoding/json"

	"github.com/sirupsen/logrus"

	domainApp "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/app"
	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
	"github.com/gofiber/contrib/v3/websocket"
	"github.com/gofiber/fiber/v3"
)

type client struct {
	// userID is the authenticated user owning this connection (0 when auth is
	// disabled). Used to scope device broadcasts per user.
	userID int64
}

type BroadcastMessage struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Result  any    `json:"result"`
}

var (
	Clients    = make(map[*websocket.Conn]client)
	Register   = make(chan *websocket.Conn)
	Broadcast  = make(chan BroadcastMessage)
	Unregister = make(chan *websocket.Conn)
)

// deviceOwnerResolver, when set, reports the owning user id of a device.
// Broadcasts carrying a device_id are only delivered to connections of that
// device's owner. Set at startup via SetDeviceOwnerResolver.
var deviceOwnerResolver func(deviceID string) (int64, bool)

func SetDeviceOwnerResolver(resolver func(deviceID string) (int64, bool)) {
	deviceOwnerResolver = resolver
}

func handleRegister(conn *websocket.Conn) {
	var userID int64
	if v, ok := conn.Locals("user_id").(int64); ok {
		userID = v
	}
	Clients[conn] = client{userID: userID}
	logrus.Println("connection registered")
}

func handleUnregister(conn *websocket.Conn) {
	delete(Clients, conn)
	logrus.Println("connection unregistered")
}

func broadcastMessage(message BroadcastMessage) {
	marshalMessage, err := json.Marshal(message)
	if err != nil {
		logrus.Println("marshal error:", err)
		return
	}

	deviceID, hasDeviceID := messageDeviceID(message)

	for conn, cli := range Clients {
		// A device-scoped broadcast goes only to connections of that device's
		// owner; everything else reaches every connection.
		if hasDeviceID && deviceID != "" && deviceOwnerResolver != nil {
			if owner, owned := deviceOwnerResolver(deviceID); owned && cli.userID != owner {
				continue
			}
		}
		if err := conn.WriteMessage(websocket.TextMessage, marshalMessage); err != nil {
			logrus.Println("write error:", err)
			closeConnection(conn)
		}
	}
}

// messageDeviceID extracts a device_id from a broadcast's Result map.
func messageDeviceID(message BroadcastMessage) (string, bool) {
	result, ok := message.Result.(map[string]any)
	if !ok {
		return "", false
	}
	deviceID, ok := result["device_id"].(string)
	return deviceID, ok
}

func closeConnection(conn *websocket.Conn) {
	if err := conn.WriteMessage(websocket.CloseMessage, []byte{}); err != nil {
		logrus.Println("write close message error:", err)
	}
	if err := conn.Close(); err != nil {
		logrus.Println("close connection error:", err)
	}
	delete(Clients, conn)
}

func RunHub() {
	for {
		select {
		case conn := <-Register:
			handleRegister(conn)

		case conn := <-Unregister:
			handleUnregister(conn)

		case message := <-Broadcast:
			logrus.Println("message received:", message)
			broadcastMessage(message)
		}
	}
}

func RegisterRoutes(app fiber.Router, service domainApp.IAppUsecase) {
	app.Use("/ws", func(c fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return c.SendStatus(fiber.StatusUpgradeRequired)
	})

	app.Get("/ws", websocket.New(func(conn *websocket.Conn) {
		defer func() {
			Unregister <- conn
			_ = conn.Close()
		}()

		Register <- conn

		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					logrus.Println("read error:", err)
				}
				return
			}

			if messageType == websocket.TextMessage {
				var messageData BroadcastMessage
				if err := json.Unmarshal(message, &messageData); err != nil {
					logrus.Println("unmarshal error:", err)
					return
				}

if messageData.Code == "FETCH_DEVICES" {
				ctx := context.Background()
				if v, ok := conn.Locals("user_id").(int64); ok && v != 0 {
					ctx = domainChatStorage.ContextWithUser(ctx, &domainChatStorage.User{ID: v})
				}
				devices, _ := service.FetchDevices(ctx)
				Broadcast <- BroadcastMessage{
					Code:    "LIST_DEVICES",
					Message: "Device found",
					Result:  devices,
				}
			}
			} else {
				logrus.Println("unsupported message type:", messageType)
			}
		}
	}))
}
