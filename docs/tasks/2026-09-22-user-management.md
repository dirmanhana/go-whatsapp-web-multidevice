# Task: Manajemen User & Admin

Tanggal: 2026-09-22 — **SELESAI (21/21 smoke check lulus)**
Repo: `go-whatsapp-web-multidevice` (branch `multiuser`)
Service: `gowa-wa-chatetin.service` (port 3001, cwd `src/`)

## T1 — Akun admin `dirmanhana@gmail.com`

- [x] 1.1 Cek keberadaan user dengan email `dirmanhana@gmail.com` — **tidak ada**
      (yang mirip `dirmanhana2@gmail.com` adalah akun berbeda, tidak diubah)
- [x] 1.2 Akun dibuat baru: id **6**, username **`dirmanhana`** (turunan local-part
      email), `is_admin=1`, password `Rifdahana290112#` (bcrypt cost 10)
- [x] 1.3 Login via `POST /auth/login` memakai email terverifikasi, `is_admin=true`

## T2 — Sistem administrasi (khusus admin) untuk kelola user

- [x] 2.1 Storage: `UpdateUser`, `SetUserPassword`, `DeleteUser`
      (`domains/chatstorage/interfaces.go`, `sqlite_repository.go`, `chatstorage_wrapper.go`)
- [x] 2.2 Domain: `AdminCreateUserRequest`, `AdminUpdateUserRequest`,
      `AdminPasswordRequest` + 4 metode interface di `domains/auth/auth.go`
- [x] 2.3 Error baru di `pkg/error/auth_error.go`: `ErrCannotDeleteSelf`,
      `ErrCannotDemoteSelf`, `ErrUserOwnsDevices`, `ErrCurrentPasswordBad`,
      `ErrUserNotFound`
- [x] 2.4 Validasi di `validations/auth_validation.go` (+ 5 test baru)
- [x] 2.5 Usecase `AdminCreateUser`, `AdminUpdateUser`, `AdminSetUserPassword`,
      `AdminDeleteUser` — semua lewat `requireAdmin` (+ `usecase/auth_manage_test.go`)
- [x] 2.6 REST: `POST /auth/users`, `PUT /auth/users/:id`,
      `POST /auth/users/:id/password`, `DELETE /auth/users/:id`
- [x] 2.7 UI `/admin`: tabel user + tambah, edit, ganti password, enable/disable, hapus

## T3 — Pengaturan akun mandiri (ganti password & email sendiri)

- [x] 3.1 Usecase `ChangeOwnPassword`, `ChangeOwnEmail` — verifikasi password saat
      ini, unik email, sesi dicabut saat ganti password (+ test)
- [x] 3.2 REST: `POST /auth/me/password`, `POST /auth/me/email`
- [x] 3.3 UI `/account` + tombol **Account**/**Users** di dashboard
      (`uiasset/auth_patch.go`, poin 5; tombol Users hanya muncul kalau `/auth/me`
      bilang `is_admin`)
- [x] 3.4 Test validasi

## T4 — Build, test, deploy

- [x] 4.1 `cd src && go vet ./...` bersih; `go test ./...` seluruh paket lulus
- [x] 4.2 `cd src && go build -o whatsapp`
- [x] 4.3 `systemctl restart gowa-wa-chatetin.service` → `active`, `/health` 200
- [x] 4.4 Smoke test end-to-end 21/21 (skrip: `/tmp/opencode/smoke_admin.sh`),
      data sementara sudah dibersihkan, sesi uji dicabut

## Catatan desain

- Panel `/admin` dan halaman `/account` menyajikan HTML shell saja (tanpa data);
  semua data diambil JS lewat endpoint yang tetap terproteksi `AuthMiddleware`.
  Shell masuk daftar path publik di `middleware.isPublicAuthPath` — sama seperti
  dashboard `/` yang juga publik.
- Otorisasi tetap di server: semua endpoint admin memakai `requireAdmin`
  (cek `is_admin`), jadi menyembunyikan tombol di UI bukan pertahanan.
- Hanya boleh menghapus user yang tidak lagi punya device (`owner_user_id`);
  token sesi target selalu dicabut saat hapus / reset password.
- Admin tidak bisa menghapus diri sendiri maupun mencabut flag admin diri sendiri,
  supaya deployment tidak pernah kehilangan admin terakhir.
- Halaman dibangun dari `src/ui/rest/templates/` (`admin.html`, `account.html`,
  `app.css`, `app.js`) yang di-inline saat serve (`ui/rest/pages.go`),
  `{{BASE_PATH}}` disubstitusi agar tetap jalan di balik `AppBasePath`.

## File yang diubah/ditambah

| File | Perubahan |
|------|-----------|
| `src/domains/chatstorage/interfaces.go` | + `UpdateUser`, `SetUserPassword`, `DeleteUser` |
| `src/infrastructure/chatstorage/sqlite_repository.go` | implementasi 3 metode di atas |
| `src/infrastructure/whatsapp/chatstorage_wrapper.go` | passthrough 3 metode |
| `src/domains/auth/auth.go` | + 5 DTO, + 6 metode `IAuthUsecase` |
| `src/pkg/error/auth_error.go` | + 5 error |
| `src/validations/auth_validation.go` | + 5 validator, `ValidateRegisterRequest` dipakai ulang via `validateAccountShape` |
| `src/usecase/auth.go` | + 7 fungsi usecase + helper `adminInfo` |
| `src/ui/rest/auth.go` | + 6 route/handler, helper `parseUserID` |
| `src/ui/rest/pages.go` | **baru** — serve `/admin`, `/account` |
| `src/ui/rest/templates/{admin,account}.html`, `app.css`, `app.js` | **baru** |
| `src/ui/rest/middleware/auth.go` | `/admin`, `/account` jadi path publik |
| `src/cmd/rest.go` | wiring `rest.InitRestPages` |
| `src/infrastructure/uiasset/auth_patch.go` | + tombol Account/Users di dashboard |
| test | `usecase/auth_manage_test.go` (baru), `usecase/auth_test.go` (stub), `validations/auth_validation_test.go`, `infrastructure/chatstorage/sqlite_repository_auth_test.go`, `infrastructure/uiasset/auth_patch_test.go` |
| `docs/tasks/2026-09-22-user-management.md` | **baru** — dokumen ini |
