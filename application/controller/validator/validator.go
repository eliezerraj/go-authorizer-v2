package validator

import (
	"context"
	"errors"
	"github.com/go-authorizer-v2/application/domain/external"
)

// Schema struct defines a validation schema for product requests.
type Schema struct {
    Validate func(context.Context, any) error
}

// Use in ProductAdd and ProductPut.
func (s *Schema)LoginSchema() Schema {
    return Schema{
        Validate: func(ctx context.Context, data any) error {
            
			req, ok := data.(external.LoginRequest)
			if !ok {
                return errors.New("schema validation failed ! Please check the request body and try again.")
            }

            if req.ClientID == "" {
                return errors.New("schema validation failed ! field client_id is mandatory")
            }

            if req.SecretID == "" {
                return errors.New("schema validation failed ! field secret_id is mandatory")
            }

            return nil
        },
    }
}
