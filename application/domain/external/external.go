package external

type LoginRequest struct {
	ClientID string `json:"client_id" validate:"required"`
	SecretID string `json:"secret_id" validate:"required"`
}

type LoginResponse struct {
	Response string `json:"response"`
	Login    any `json:"login" validate:"required"`
}

type VerifyJWTRequest struct {
	Token string `json:"access_token" validate:"required"`
}

type VerifyJWTResponse struct {
	Response string `json:"response"`
	Claims   any `json:"claims" validate:"required"`
}
