//
// Copyright 2021, Sander van Harmelen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package gitlab

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"

	"github.com/google/go-querystring/query"
	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

// RequestOptionFunc can be passed to all API requests to customize the API request.
type RequestOptionFunc func(req *retryablehttp.Request, opt interface{}) error

// WithContext runs the request with the provided context
func WithContext(ctx context.Context) RequestOptionFunc {
	return func(req *retryablehttp.Request, opt interface{}) error {
		*req = *req.WithContext(ctx)
		return nil
	}
}

// WithFile transforms the request to a multipart request with a file.
func WithFile(content io.Reader, filename string, uploadType UploadType) RequestOptionFunc {
	return func(req *retryablehttp.Request, opt interface{}) error {
		b := new(bytes.Buffer)
		w := multipart.NewWriter(b)

		fw, err := w.CreateFormFile(string(uploadType), filename)
		if err != nil {
			return err
		}

		if _, err := io.Copy(fw, content); err != nil {
			return err
		}

		if opt != nil {
			fields, err := query.Values(opt)
			if err != nil {
				return err
			}
			for name := range fields {
				if err = w.WriteField(name, fmt.Sprintf("%v", fields.Get(name))); err != nil {
					return err
				}
			}
		}

		if err = w.Close(); err != nil {
			return err
		}

		// Set the buffer as the request body.
		if err = req.SetBody(b); err != nil {
			return err
		}

		// Overwrite the default content type.
		req.Header.Set("Content-Type", w.FormDataContentType())

		return nil
	}
}

// WithSudo takes either a username or user ID and sets the SUDO request header.
func WithSudo(uid interface{}) RequestOptionFunc {
	return func(req *retryablehttp.Request, opt interface{}) error {
		user, err := parseID(uid)
		if err != nil {
			return err
		}
		req.Header.Set("SUDO", user)
		return nil
	}
}

// WithToken takes a token which is then used when making this one request.
func WithToken(authType AuthType, token string) RequestOptionFunc {
	return func(req *retryablehttp.Request, opt interface{}) error {
		switch authType {
		case JobToken:
			req.Header.Set("JOB-TOKEN", token)
		case OAuthToken:
			req.Header.Set("Authorization", "Bearer "+token)
		case PrivateToken:
			req.Header.Set("PRIVATE-TOKEN", token)
		}
		return nil
	}
}
