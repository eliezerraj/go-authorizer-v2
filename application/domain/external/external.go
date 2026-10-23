package external

type LoginRequest struct {
	ClientID string `json:"client_id" validate:"required"`
	SecretID string `json:"secret_id" validate:"required"`
}

type VerifyJWTRequest struct {
	Token string `json:"access_token" validate:"required"`
}

type VerifyJWTResponse struct {
	Response string `json:"response"`
	Claims   any `json:"claims" validate:"required"`
}

type AuthTokenRequest struct {
	ClientID string `json:"client_id" form:"client_id" validate:"required"`
	SecretID string `json:"secret_id" form:"secret_id"`
	Resource string `json:"resource" form:"resource" validate:"required"`
	GrantType string `json:"grant_type" form:"grant_type" validate:"required"` // TokenExchange, ClientCredentials, AuthorizationCode.
	ClientAssertion     string `json:"client_assertion" form:"client_assertion"`
	ClientAssertionType string `json:"client_assertion_type" form:"client_assertion_type"`
}
