package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/service"
)

var avatarKeyPattern = regexp.MustCompile(`^avatars/user-\d+/[0-9a-fA-F-]{36}\.(jpg|png)$`)

type avatarUploadData struct {
	ObjectKey  string `json:"object_key"`
	AvatarURL  string `json:"avatar_url"`
	FileSize   int64  `json:"file_size"`
	UploadedAt string `json:"uploaded_at"`
}

func TestAvatarUploadJPEGStoresInMinIOWithMetadata(t *testing.T) {
	env := newMinIOIntegrationEnv(t)
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{storageSvc: env.storage})
	defer closeFn()

	registerAndLogin(t, client, baseURL, "avatar-jpeg@example.com", "Valid#Pass1234")
	csrf := cookieValue(t, client, baseURL, "csrf_token")

	fileContent := jpegFixtureBytes()
	resp, envelope, rawBody := uploadAvatarMultipart(t, client, baseURL+"/api/v1/me/avatar", "avatar.jpg", fileContent, "image/jpeg", map[string]string{
		"X-CSRF-Token": csrf,
	})
	if resp.StatusCode != http.StatusOK || !envelope.Success {
		t.Fatalf("upload jpeg failed: status=%d body=%s", resp.StatusCode, rawBody)
	}

	var payload avatarUploadData
	if err := json.Unmarshal(envelope.Data, &payload); err != nil {
		t.Fatalf("decode upload payload: %v", err)
	}
	if !avatarKeyPattern.MatchString(payload.ObjectKey) {
		t.Fatalf("unexpected object key format: %q", payload.ObjectKey)
	}
	if !strings.Contains(payload.AvatarURL, payload.ObjectKey) {
		t.Fatalf("expected avatar_url to contain object key: url=%q key=%q", payload.AvatarURL, payload.ObjectKey)
	}
	if payload.FileSize != int64(len(fileContent)) {
		t.Fatalf("expected file size %d, got %d", len(fileContent), payload.FileSize)
	}
	if payload.UploadedAt == "" {
		t.Fatalf("expected uploaded_at to be present")
	}

	obj := env.mustStatObject(t, payload.ObjectKey)
	if obj.ContentType != "image/jpeg" {
		t.Fatalf("expected content type image/jpeg, got %q", obj.ContentType)
	}
	assertObjectMetadataContains(t, obj.UserMetadata, "user-id", "1")
	assertObjectMetadataContains(t, obj.UserMetadata, "detected-content-type", "image/jpeg")
	assertObjectMetadataKeyExists(t, obj.UserMetadata, "uploaded-at")
}

func TestAvatarUploadPNGAndDeleteFlow(t *testing.T) {
	env := newMinIOIntegrationEnv(t)
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{storageSvc: env.storage})
	defer closeFn()

	registerAndLogin(t, client, baseURL, "avatar-png@example.com", "Valid#Pass1234")
	csrf := cookieValue(t, client, baseURL, "csrf_token")

	png := pngFixtureBytes()
	resp, envelope, rawBody := uploadAvatarMultipart(t, client, baseURL+"/api/v1/me/avatar", "avatar.png", png, "image/png", map[string]string{
		"X-CSRF-Token": csrf,
	})
	if resp.StatusCode != http.StatusOK || !envelope.Success {
		t.Fatalf("upload png failed: status=%d body=%s", resp.StatusCode, rawBody)
	}
	var payload avatarUploadData
	if err := json.Unmarshal(envelope.Data, &payload); err != nil {
		t.Fatalf("decode upload payload: %v", err)
	}
	if !strings.HasSuffix(payload.ObjectKey, ".png") {
		t.Fatalf("expected png suffix, got %q", payload.ObjectKey)
	}
	if !env.mustObjectExists(t, payload.ObjectKey) {
		t.Fatalf("expected uploaded object to exist: %q", payload.ObjectKey)
	}

	resp, delEnv := doJSON(t, client, http.MethodDelete, baseURL+"/api/v1/me/avatar", map[string]string{"object_key": payload.ObjectKey}, map[string]string{
		"X-CSRF-Token": csrf,
	})
	if resp.StatusCode != http.StatusOK || !delEnv.Success {
		t.Fatalf("delete avatar failed: status=%d error=%#v", resp.StatusCode, delEnv.Error)
	}
	if env.mustObjectExists(t, payload.ObjectKey) {
		t.Fatalf("expected object to be deleted: %q", payload.ObjectKey)
	}
}

func TestAvatarUploadValidationAndSecurity(t *testing.T) {
	env := newMinIOIntegrationEnv(t)
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{storageSvc: env.storage})
	defer closeFn()

	registerAndLogin(t, client, baseURL, "avatar-security@example.com", "Valid#Pass1234")
	csrf := cookieValue(t, client, baseURL, "csrf_token")

	t.Run("rejects oversize upload", func(t *testing.T) {
		oversize := bytes.Repeat([]byte{0xFF, 0xD8, 0xFF, 0xE0}, (6*1024*1024)/4)
		resp, env, _ := uploadAvatarMultipart(t, client, baseURL+"/api/v1/me/avatar", "big.jpg", oversize, "image/jpeg", map[string]string{
			"X-CSRF-Token": csrf,
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
		if env.Error == nil || env.Error.Code != "BAD_REQUEST" {
			t.Fatalf("expected BAD_REQUEST from multipart/body-limit enforcement, got %#v", env.Error)
		}
	})

	t.Run("rejects spoofed content type", func(t *testing.T) {
		spoofed := []byte("this is not an image")
		resp, env, _ := uploadAvatarMultipart(t, client, baseURL+"/api/v1/me/avatar", "spoofed.jpg", spoofed, "image/jpeg", map[string]string{
			"X-CSRF-Token": csrf,
		})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", resp.StatusCode)
		}
		if env.Error == nil || env.Error.Code != "INVALID_FILE_TYPE" {
			t.Fatalf("expected INVALID_FILE_TYPE, got %#v", env.Error)
		}
	})

	t.Run("rejects missing csrf", func(t *testing.T) {
		resp, body := uploadAvatarMultipartRaw(t, client, baseURL+"/api/v1/me/avatar", "avatar.jpg", jpegFixtureBytes(), "image/jpeg", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403, got %d body=%s", resp.StatusCode, body)
		}
		if !strings.Contains(body, "invalid csrf token") {
			t.Fatalf("expected csrf error, got body=%q", body)
		}
	})
}

func TestAvatarDeleteOwnershipAndPathTraversal(t *testing.T) {
	minioEnv := newMinIOIntegrationEnv(t)
	baseURL, clientA, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{storageSvc: minioEnv.storage})
	defer closeFn()
	clientB := newSessionClient(t)

	registerAndLogin(t, clientA, baseURL, "avatar-owner-a@example.com", "Valid#Pass1234")
	registerAndLogin(t, clientB, baseURL, "avatar-owner-b@example.com", "Valid#Pass1234")

	csrfA := cookieValue(t, clientA, baseURL, "csrf_token")
	csrfB := cookieValue(t, clientB, baseURL, "csrf_token")

	resp, uploadEnv, rawBody := uploadAvatarMultipart(t, clientA, baseURL+"/api/v1/me/avatar", "avatar.jpg", jpegFixtureBytes(), "image/jpeg", map[string]string{
		"X-CSRF-Token": csrfA,
	})
	if resp.StatusCode != http.StatusOK || !uploadEnv.Success {
		t.Fatalf("upload failed: status=%d body=%s", resp.StatusCode, rawBody)
	}
	var payload avatarUploadData
	if err := json.Unmarshal(uploadEnv.Data, &payload); err != nil {
		t.Fatalf("decode upload payload: %v", err)
	}

	resp, deleteEnv := doJSON(t, clientB, http.MethodDelete, baseURL+"/api/v1/me/avatar", map[string]string{"object_key": payload.ObjectKey}, map[string]string{
		"X-CSRF-Token": csrfB,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-user delete, got %d", resp.StatusCode)
	}
	if deleteEnv.Error == nil || deleteEnv.Error.Code != "FORBIDDEN" {
		t.Fatalf("expected FORBIDDEN, got %#v", deleteEnv.Error)
	}
	if !minioEnv.mustObjectExists(t, payload.ObjectKey) {
		t.Fatalf("object should remain after forbidden delete")
	}

	resp, deleteEnv = doJSON(t, clientA, http.MethodDelete, baseURL+"/api/v1/me/avatar", map[string]string{"object_key": "avatars/user-1/../user-2/x.jpg"}, map[string]string{
		"X-CSRF-Token": csrfA,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for path traversal, got %d", resp.StatusCode)
	}
	if deleteEnv.Error == nil || deleteEnv.Error.Code != "FORBIDDEN" {
		t.Fatalf("expected FORBIDDEN for traversal, got %#v", deleteEnv.Error)
	}
}

func TestAvatarUploadHandlesMinIOUnavailable(t *testing.T) {
	storage, err := service.NewMinIOStorageService("127.0.0.1:1", "minioadmin", "minioadmin", "avatars-test", false)
	if err != nil {
		t.Fatalf("create storage service: %v", err)
	}

	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{storageSvc: storage})
	defer closeFn()

	registerAndLogin(t, client, baseURL, "avatar-minio-down@example.com", "Valid#Pass1234")
	csrf := cookieValue(t, client, baseURL, "csrf_token")

	resp, env, _ := uploadAvatarMultipart(t, client, baseURL+"/api/v1/me/avatar", "avatar.jpg", jpegFixtureBytes(), "image/jpeg", map[string]string{
		"X-CSRF-Token": csrf,
	})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 when minio unavailable, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "INTERNAL" {
		t.Fatalf("expected INTERNAL error envelope, got %#v", env.Error)
	}
}

func TestAvatarUploadConcurrentUsersNoKeyConflicts(t *testing.T) {
	minioEnv := newMinIOIntegrationEnv(t)
	baseURL, _, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{storageSvc: minioEnv.storage})
	defer closeFn()

	const n = 5
	type userSession struct {
		client *http.Client
		csrf   string
	}
	sessions := make([]userSession, 0, n)
	for i := range n {
		client, err := newSessionClientNoFail()
		if err != nil {
			t.Fatalf("create session client for user %d: %v", i, err)
		}
		email := fmt.Sprintf("avatar-concurrent-%d@example.com", i)
		csrf, err := registerAndLoginNoFail(client, baseURL, email, "Valid#Pass1234")
		if err != nil {
			t.Fatalf("register/login user %d: %v", i, err)
		}
		sessions = append(sessions, userSession{client: client, csrf: csrf})
	}

	keys := make(chan string, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup

	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status, uploadEnv, err := uploadAvatarMultipartNoFail(sessions[i].client, baseURL+"/api/v1/me/avatar", fmt.Sprintf("avatar-%d.jpg", i), jpegFixtureBytes(), "image/jpeg", map[string]string{
				"X-CSRF-Token": sessions[i].csrf,
			})
			if err != nil {
				errs <- fmt.Errorf("upload request user %d: %w", i, err)
				return
			}
			if status != http.StatusOK || !uploadEnv.Success {
				errs <- fmt.Errorf("upload failed for user %d: status=%d err=%#v", i, status, uploadEnv.Error)
				return
			}
			var payload avatarUploadData
			if err := json.Unmarshal(uploadEnv.Data, &payload); err != nil {
				errs <- fmt.Errorf("decode payload user %d: %w", i, err)
				return
			}
			keys <- payload.ObjectKey
		}(i)
	}
	wg.Wait()
	close(keys)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	seen := map[string]struct{}{}
	for key := range keys {
		if _, ok := seen[key]; ok {
			t.Fatalf("duplicate object key generated: %q", key)
		}
		seen[key] = struct{}{}
		if !minioEnv.mustObjectExists(t, key) {
			t.Fatalf("expected object to exist after concurrent upload: %q", key)
		}
	}
	if len(seen) != n {
		t.Fatalf("expected %d uploaded keys, got %d", n, len(seen))
	}
}

func uploadAvatarMultipart(t *testing.T, client *http.Client, url, filename string, fileContent []byte, contentType string, headers map[string]string) (*http.Response, apiEnvelope, string) {
	t.Helper()
	resp, body := uploadAvatarMultipartRaw(t, client, url, filename, fileContent, contentType, headers)
	var env apiEnvelope
	if body != "" {
		_ = json.Unmarshal([]byte(body), &env)
	}
	return resp, env, body
}

func uploadAvatarMultipartRaw(t *testing.T, client *http.Client, url, filename string, fileContent []byte, contentType string, headers map[string]string) (*http.Response, string) {
	t.Helper()

	payload := &bytes.Buffer{}
	writer := multipart.NewWriter(payload)
	partHeaders := make(textproto.MIMEHeader)
	partHeaders.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "avatar", filename))
	partHeaders.Set("Content-Type", contentType)
	part, err := writer.CreatePart(partHeaders)
	if err != nil {
		t.Fatalf("create multipart file part: %v", err)
	}
	if _, err := part.Write(fileContent); err != nil {
		t.Fatalf("write multipart file part: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, payload)
	if err != nil {
		t.Fatalf("create upload request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("execute upload request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.String()
}

func jpegFixtureBytes() []byte {
	return append([]byte{
		0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,
		0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
		0x00, 0x01, 0x00, 0x00,
	}, bytes.Repeat([]byte{0x11}, 1024)...)
}

func pngFixtureBytes() []byte {
	return append([]byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01,
	}, bytes.Repeat([]byte{0x22}, 1024)...)
}

func assertObjectMetadataContains(t *testing.T, metadata map[string]string, partialKey, expectedValue string) {
	t.Helper()
	for key, value := range metadata {
		if strings.Contains(strings.ToLower(key), strings.ToLower(partialKey)) && value == expectedValue {
			return
		}
	}
	t.Fatalf("expected metadata key containing %q with value %q, got %#v", partialKey, expectedValue, metadata)
}

func assertObjectMetadataKeyExists(t *testing.T, metadata map[string]string, partialKey string) {
	t.Helper()
	for key, value := range metadata {
		if strings.Contains(strings.ToLower(key), strings.ToLower(partialKey)) && strings.TrimSpace(value) != "" {
			if _, err := time.Parse(time.RFC3339, value); err == nil {
				return
			}
		}
	}
	t.Fatalf("expected metadata key containing %q with RFC3339 value, got %#v", partialKey, metadata)
}

func newSessionClientNoFail() (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &http.Client{Jar: jar}, nil
}

func registerAndLoginNoFail(client *http.Client, baseURL, email, password string) (string, error) {
	registerBody := map[string]string{
		"email":    email,
		"name":     "Concurrent User",
		"password": password,
	}
	status, env, err := doJSONNoFail(client, http.MethodPost, baseURL+"/api/v1/auth/local/register", registerBody, nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated || !env.Success {
		return "", fmt.Errorf("register status=%d error=%#v", status, env.Error)
	}

	loginBody := map[string]string{
		"email":    email,
		"password": password,
	}
	status, env, err = doJSONNoFail(client, http.MethodPost, baseURL+"/api/v1/auth/local/login", loginBody, nil)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK || !env.Success {
		return "", fmt.Errorf("login status=%d error=%#v", status, env.Error)
	}

	u, err := url.Parse(baseURL + "/api/v1/auth/refresh")
	if err != nil {
		return "", err
	}
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == "csrf_token" {
			return c.Value, nil
		}
	}
	return "", fmt.Errorf("csrf cookie not found")
}

func doJSONNoFail(client *http.Client, method, endpoint string, body any, headers map[string]string) (int, apiEnvelope, error) {
	resp, raw, err := doRawTextNoFail(client, method, endpoint, body, headers)
	if err != nil {
		return 0, apiEnvelope{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	var env apiEnvelope
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &env)
	}
	return resp.StatusCode, env, nil
}

func uploadAvatarMultipartNoFail(client *http.Client, endpoint, filename string, fileContent []byte, contentType string, headers map[string]string) (int, apiEnvelope, error) {
	payload := &bytes.Buffer{}
	writer := multipart.NewWriter(payload)
	partHeaders := make(textproto.MIMEHeader)
	partHeaders.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "avatar", filename))
	partHeaders.Set("Content-Type", contentType)
	part, err := writer.CreatePart(partHeaders)
	if err != nil {
		return 0, apiEnvelope{}, err
	}
	if _, err := part.Write(fileContent); err != nil {
		return 0, apiEnvelope{}, err
	}
	if err := writer.Close(); err != nil {
		return 0, apiEnvelope{}, err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, payload)
	if err != nil {
		return 0, apiEnvelope{}, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, apiEnvelope{}, err
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, apiEnvelope{}, err
	}
	_ = resp.Body.Close()

	var env apiEnvelope
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &env)
	}
	return resp.StatusCode, env, nil
}

func doRawTextNoFail(client *http.Client, method, endpoint string, body any, headers map[string]string) (*http.Response, string, error) {
	var payload []byte
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, "", err
		}
		payload = raw
	}
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	_ = resp.Body.Close()
	return resp, string(raw), nil
}
