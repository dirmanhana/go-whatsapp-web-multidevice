package chatstorage

import (
	"testing"
	"time"

	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
)

func TestUserAndTokenRoundTrip(t *testing.T) {
	repo := newTestSQLiteRepository(t)

	id, err := repo.CreateUser("alice", "hash-of-password")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero user id")
	}

	user, err := repo.GetUserByUsername("alice")
	if err != nil {
		t.Fatalf("get user by username: %v", err)
	}
	if user == nil || user.ID != id || user.PasswordHash != "hash-of-password" {
		t.Fatalf("unexpected user: %+v", user)
	}

	// Case-insensitive username lookup
	user, err = repo.GetUserByUsername("ALICE")
	if err != nil || user == nil {
		t.Fatalf("case-insensitive lookup failed: user=%+v err=%v", user, err)
	}

	byID, err := repo.GetUserByID(id)
	if err != nil || byID == nil || byID.Username != "alice" {
		t.Fatalf("get user by id failed: user=%+v err=%v", byID, err)
	}

	// Duplicate username is rejected by the unique index
	if _, err := repo.CreateUser("alice", "other-hash"); err == nil {
		t.Fatal("expected duplicate username to fail")
	}

	// Tokens: only a non-expired token resolves the user
	deadHash := "deadbeef"
	if err := repo.CreateAuthToken(deadHash, id, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("create expired token: %v", err)
	}
	user, err = repo.GetUserByTokenHash(deadHash)
	if err != nil || user != nil {
		t.Fatalf("expired token must not resolve: user=%+v err=%v", user, err)
	}

	liveHash := "cafebabe"
	if err := repo.CreateAuthToken(liveHash, id, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create live token: %v", err)
	}
	user, err = repo.GetUserByTokenHash(liveHash)
	if err != nil || user == nil || user.ID != id {
		t.Fatalf("live token must resolve user: user=%+v err=%v", user, err)
	}

	// Delete revokes the token
	if err := repo.DeleteAuthToken(liveHash); err != nil {
		t.Fatalf("delete token: %v", err)
	}
	user, err = repo.GetUserByTokenHash(liveHash)
	if err != nil || user != nil {
		t.Fatalf("deleted token must not resolve: user=%+v err=%v", user, err)
	}
}

func TestDeleteExpiredAuthTokens(t *testing.T) {
	repo := newTestSQLiteRepository(t)

	id, err := repo.CreateUser("bob", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := repo.CreateAuthToken("expired-1", id, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("create expired token: %v", err)
	}
	if err := repo.CreateAuthToken("live-1", id, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create live token: %v", err)
	}

	if err := repo.DeleteExpiredAuthTokens(); err != nil {
		t.Fatalf("delete expired tokens: %v", err)
	}

	if user, _ := repo.GetUserByTokenHash("expired-1"); user != nil {
		t.Fatal("expired token still resolves after cleanup")
	}
	if user, _ := repo.GetUserByTokenHash("live-1"); user == nil {
		t.Fatal("live token must survive cleanup")
	}
}

func TestDeviceOwnerClaim(t *testing.T) {
	repo := newTestSQLiteRepository(t)

	if err := repo.SaveDeviceRecord(&domainChatStorage.DeviceRecord{
		DeviceID:    "slot-1",
		DisplayName: "Slot 1",
	}); err != nil {
		t.Fatalf("save device record: %v", err)
	}

	userID, err := repo.CreateUser("carol", "hash")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Unclaimed slot can be claimed by the first user
	claimed, err := repo.SetDeviceOwner("slot-1", userID)
	if err != nil || !claimed {
		t.Fatalf("expected claim to succeed: claimed=%v err=%v", claimed, err)
	}
	if count, err := repo.CountUserDevices(userID); err != nil || count != 1 {
		t.Fatalf("expected 1 owned device, got %d (err=%v)", count, err)
	}

	// A second user cannot steal the claim
	otherID, err := repo.CreateUser("dave", "hash")
	if err != nil {
		t.Fatalf("create other user: %v", err)
	}
	claimed, err = repo.SetDeviceOwner("slot-1", otherID)
	if err != nil || claimed {
		t.Fatalf("expected claim by other user to fail: claimed=%v err=%v", claimed, err)
	}

	// The owning user can re-claim idempotently (no error)
	claimed, err = repo.SetDeviceOwner("slot-1", userID)
	if err != nil || !claimed {
		t.Fatalf("expected re-claim by owner to succeed: claimed=%v err=%v", claimed, err)
	}

	// Owner round-trips through the registry record
	rec, err := repo.GetDeviceRecord("slot-1")
	if err != nil || rec == nil || rec.OwnerUserID != userID {
		t.Fatalf("expected record owner %d, got %+v (err=%v)", userID, rec, err)
	}

	// SaveDeviceRecord without an owner preserves the existing claim
	if err := repo.SaveDeviceRecord(&domainChatStorage.DeviceRecord{
		DeviceID:    "slot-1",
		DisplayName: "Slot 1 renamed",
	}); err != nil {
		t.Fatalf("save record without owner: %v", err)
	}
	rec, err = repo.GetDeviceRecord("slot-1")
	if err != nil || rec == nil || rec.OwnerUserID != userID {
		t.Fatalf("owner must survive ownerless update, got %+v (err=%v)", rec, err)
	}

	// Count scopes per user
	if count, err := repo.CountUserDevices(otherID); err != nil || count != 0 {
		t.Fatalf("expected other user to own 0 devices, got %d (err=%v)", count, err)
	}
}