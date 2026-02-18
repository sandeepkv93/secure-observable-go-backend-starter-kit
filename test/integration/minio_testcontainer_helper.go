package integration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/service"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const defaultMinioTestImage = "docker.io/minio/minio:RELEASE.2025-09-07T16-13-09Z"

type minioIntegrationEnv struct {
	endpoint string
	bucket   string
	access   string
	secret   string

	storage *service.MinIOStorageService
	client  *minio.Client

	container testcontainers.Container
}

func newMinIOIntegrationEnv(t *testing.T) *minioIntegrationEnv {
	t.Helper()

	ctx := context.Background()
	image := os.Getenv("MINIO_TEST_IMAGE")
	if strings.TrimSpace(image) == "" {
		image = defaultMinioTestImage
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: image,
			Env: map[string]string{
				"MINIO_ROOT_USER":     "minioadmin",
				"MINIO_ROOT_PASSWORD": "minioadmin",
			},
			ExposedPorts: []string{"9000/tcp"},
			Cmd:          []string{"server", "/data", "--address", ":9000"},
			WaitingFor: wait.ForListeningPort("9000/tcp").
				WithStartupTimeout(45 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start minio test container: %v", err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(ctx)
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("resolve minio host: %v", err)
	}
	mappedPort, err := container.MappedPort(ctx, "9000/tcp")
	if err != nil {
		t.Fatalf("resolve minio port: %v", err)
	}
	endpoint := net.JoinHostPort(host, mappedPort.Port())
	bucket := fmt.Sprintf("avatars-it-%d", time.Now().UnixNano())

	storage, err := service.NewMinIOStorageService(endpoint, "minioadmin", "minioadmin", bucket, false)
	if err != nil {
		t.Fatalf("create minio storage service: %v", err)
	}
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4("minioadmin", "minioadmin", ""),
		Secure: false,
	})
	if err != nil {
		t.Fatalf("create minio verification client: %v", err)
	}
	waitForMinIOReady(t, client)

	return &minioIntegrationEnv{
		endpoint:  endpoint,
		bucket:    bucket,
		access:    "minioadmin",
		secret:    "minioadmin",
		storage:   storage,
		client:    client,
		container: container,
	}
}

func waitForMinIOReady(t *testing.T, client *minio.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	for {
		_, err := client.ListBuckets(ctx)
		if err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("minio readiness check timed out: %v", err)
		case <-ticker.C:
		}
	}
}

func (e *minioIntegrationEnv) mustObjectExists(t *testing.T, objectKey string) bool {
	t.Helper()
	_, err := e.client.StatObject(context.Background(), e.bucket, objectKey, minio.StatObjectOptions{})
	if err == nil {
		return true
	}
	if isObjectNotFound(err) {
		return false
	}
	t.Fatalf("stat minio object %q: %v", objectKey, err)
	return false
}

func (e *minioIntegrationEnv) mustStatObject(t *testing.T, objectKey string) minio.ObjectInfo {
	t.Helper()
	obj, err := e.client.StatObject(context.Background(), e.bucket, objectKey, minio.StatObjectOptions{})
	if err != nil {
		t.Fatalf("stat minio object %q: %v", objectKey, err)
	}
	return obj
}

func isObjectNotFound(err error) bool {
	var errResp minio.ErrorResponse
	if errors.As(err, &errResp) {
		return errResp.Code == "NoSuchKey" || errResp.Code == "NoSuchBucket"
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}
