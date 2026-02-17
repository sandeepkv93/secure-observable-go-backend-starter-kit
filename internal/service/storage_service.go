package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const (
	maxAvatarSize    = 5 * 1024 * 1024 // 5 MB
	avatarObjectTTL  = 7 * 24 * time.Hour
	presignedURLTTL  = 15 * time.Minute
	avatarPathPrefix = "avatars"
)

var (
	ErrFileTooBig           = errors.New("file size exceeds 5MB limit")
	ErrInvalidFileType      = errors.New("invalid file type, only JPEG and PNG images are allowed")
	ErrBucketCreationFailed = errors.New("failed to create storage bucket")
	ErrUploadFailed         = errors.New("failed to upload file")
	ErrDeleteFailed         = errors.New("failed to delete file")
	ErrURLGenerationFailed  = errors.New("failed to generate presigned URL")
	ErrUnauthorizedAccess   = errors.New("unauthorized access to resource")

	allowedContentTypes = map[string]struct{}{
		"image/jpeg": {},
		"image/png":  {},
	}
)

// StorageService defines the interface for object storage operations.
type StorageService interface {
	// UploadAvatar uploads a user's avatar and returns the object key.
	UploadAvatar(ctx context.Context, userID uint, file io.Reader, fileSize int64, contentType string) (string, error)

	// DeleteAvatar deletes a user's avatar by object key.
	// Validates that the objectKey belongs to the specified userID.
	DeleteAvatar(ctx context.Context, userID uint, objectKey string) error

	// GenerateAvatarURL generates a presigned URL for avatar access.
	GenerateAvatarURL(ctx context.Context, objectKey string) (string, error)
}

// MinIOStorageService implements StorageService using MinIO/S3-compatible storage.
type MinIOStorageService struct {
	client     *minio.Client
	bucketName string
	initOnce   sync.Once
	initErr    error
}

// NewMinIOStorageService creates a MinIO-backed storage service.
// Bucket creation is deferred until the first operation to avoid blocking app startup.
func NewMinIOStorageService(endpoint, accessKey, secretKey, bucketName string, useSSL bool) (*MinIOStorageService, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("create minio client: %w", err)
	}

	return &MinIOStorageService{
		client:     client,
		bucketName: bucketName,
	}, nil
}

// lazyInit ensures the bucket exists on first use (not at startup).
func (s *MinIOStorageService) lazyInit(ctx context.Context) error {
	s.initOnce.Do(func() {
		s.initErr = s.ensureBucketExists(ctx)
	})
	return s.initErr
}

// ensureBucketExists creates the bucket if it doesn't exist.
func (s *MinIOStorageService) ensureBucketExists(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucketName)
	if err != nil {
		return fmt.Errorf("%w: check bucket existence: %v", ErrBucketCreationFailed, err)
	}

	if !exists {
		if err := s.client.MakeBucket(ctx, s.bucketName, minio.MakeBucketOptions{}); err != nil {
			return fmt.Errorf("%w: create bucket: %v", ErrBucketCreationFailed, err)
		}
	}

	return nil
}

// UploadAvatar uploads a user's avatar with validation.
// Detects content type from actual bytes to prevent spoofing.
func (s *MinIOStorageService) UploadAvatar(ctx context.Context, userID uint, file io.Reader, fileSize int64, contentType string) (string, error) {
	// Validate file size BEFORE connecting to MinIO
	if fileSize > maxAvatarSize {
		return "", ErrFileTooBig
	}

	// Read first 512 bytes to detect actual content type
	// This prevents spoofing via client-controlled Content-Type headers
	buf := make([]byte, 512)
	n, err := io.ReadFull(file, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", fmt.Errorf("%w: read file for content detection: %v", ErrUploadFailed, err)
	}
	buf = buf[:n]

	// Detect actual content type from bytes
	detectedType := http.DetectContentType(buf)
	normalizedDetectedType := strings.ToLower(strings.TrimSpace(detectedType))

	// Validate detected content type BEFORE connecting to MinIO (not client-provided one)
	if _, allowed := allowedContentTypes[normalizedDetectedType]; !allowed {
		return "", ErrInvalidFileType
	}

	// Lazy init AFTER validation passes (defers MinIO connection until necessary)
	if err := s.lazyInit(ctx); err != nil {
		return "", err
	}

	// Combine sniffed bytes with remaining file content
	fullFile := io.MultiReader(bytes.NewReader(buf), file)

	// Generate unique object key with user namespace
	fileExt := contentTypeToExtension(normalizedDetectedType)
	objectKey := fmt.Sprintf("%s/user-%d/%s%s", avatarPathPrefix, userID, uuid.New().String(), fileExt)

	// Prepare metadata
	metadata := map[string]string{
		"Detected-Content-Type": normalizedDetectedType,
		"User-ID":               fmt.Sprintf("%d", userID),
		"Uploaded-At":           time.Now().UTC().Format(time.RFC3339),
	}

	// Upload file
	_, err = s.client.PutObject(ctx, s.bucketName, objectKey, fullFile, fileSize, minio.PutObjectOptions{
		ContentType:  normalizedDetectedType,
		UserMetadata: metadata,
	})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUploadFailed, err)
	}

	return objectKey, nil
}

// DeleteAvatar deletes an avatar object after validating ownership.
// Enforces that the objectKey belongs to the specified userID.
func (s *MinIOStorageService) DeleteAvatar(ctx context.Context, userID uint, objectKey string) error {
	// No-op for empty keys (fast path, no MinIO connection needed)
	if strings.TrimSpace(objectKey) == "" {
		return nil
	}

	// Reject path traversal attempts (defense in depth, even though S3 keys are flat strings)
	if strings.Contains(objectKey, "..") {
		return ErrUnauthorizedAccess
	}

	// Validate ownership BEFORE connecting to MinIO: objectKey must match pattern avatars/user-{userID}/...
	expectedPrefix := fmt.Sprintf("%s/user-%d/", avatarPathPrefix, userID)
	if !strings.HasPrefix(objectKey, expectedPrefix) {
		return ErrUnauthorizedAccess
	}

	// Lazy init AFTER validation passes (defers MinIO connection until necessary)
	if err := s.lazyInit(ctx); err != nil {
		return err
	}

	err := s.client.RemoveObject(ctx, s.bucketName, objectKey, minio.RemoveObjectOptions{})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeleteFailed, err)
	}

	return nil
}

// GenerateAvatarURL generates a presigned GET URL for avatar access.
func (s *MinIOStorageService) GenerateAvatarURL(ctx context.Context, objectKey string) (string, error) {
	// Validate input BEFORE connecting to MinIO
	if strings.TrimSpace(objectKey) == "" {
		return "", fmt.Errorf("%w: empty object key", ErrURLGenerationFailed)
	}

	// Lazy init AFTER validation passes (defers MinIO connection until necessary)
	if err := s.lazyInit(ctx); err != nil {
		return "", err
	}

	presignedURL, err := s.client.PresignedGetObject(ctx, s.bucketName, objectKey, presignedURLTTL, url.Values{})
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrURLGenerationFailed, err)
	}

	return presignedURL.String(), nil
}

// contentTypeToExtension maps content type to file extension.
func contentTypeToExtension(contentType string) string {
	switch contentType {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	default:
		return ""
	}
}
