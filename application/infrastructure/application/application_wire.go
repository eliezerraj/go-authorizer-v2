package application

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/eliezerraj/go-core/v3/logger"
	"github.com/eliezerraj/go-core/v3/database/connector"

	"github.com/go-authorizer-v2/application/infrastructure/security"
	"github.com/go-authorizer-v2/application/infrastructure/repository"
	"github.com/go-authorizer-v2/application/config"
	"github.com/go-authorizer-v2/application/controller"
	"github.com/go-authorizer-v2/application/domain/usecase"
)

type Application struct {
	AuthorizerController *controller.AuthorizerController
}

type UseCase struct {
	LoginUseCase usecase.ILoginUseCase
}

type Repository struct {
	KeyRepository *repository.KeyRepository
}

func NewApplication(cfg *config.Config) (*Application, error) {
	logger.InfoOutCtx("initializing application SUCCESSFULLY")

	// Initialize database connector
	readerConfig := connector.ConnectorConfig{
		DSN:              "postgres://" + cfg.Database.Username + ":" + cfg.Database.Password + "@" + cfg.Database.Host + ":" + cfg.Database.Port + "/" + cfg.Database.Name,
		MaxConnIdleTime:  cfg.Database.ConnIdleTime * time.Minute,
		MaxConnLifeTime:  cfg.Database.ConnLifetime * time.Minute,
		MaxConns:         cfg.Database.MaxConnections,
		MinConns:         cfg.Database.MinConnections,
		DBConnTimeout:    cfg.Database.ConnTimeout,
		HealthCheckPeriod: cfg.Database.ConnIdleTime * time.Minute / 2,
	}

	writerConfig := connector.ConnectorConfig{
		DSN:              "postgres://" + cfg.Database.Username + ":" + cfg.Database.Password + "@" + cfg.Database.Host + ":" + cfg.Database.Port + "/" + cfg.Database.Name,
		MaxConnIdleTime:  cfg.Database.ConnIdleTime * time.Minute,
		MaxConnLifeTime:  cfg.Database.ConnLifetime * time.Minute,
		MaxConns:         cfg.Database.MaxConnections,
		MinConns:         cfg.Database.MinConnections,
		DBConnTimeout:    cfg.Database.ConnTimeout,
		HealthCheckPeriod: cfg.Database.ConnIdleTime * time.Minute / 2,
	}

	logger.InfoOutCtx("readerConfig initialized SUCCESSFULLY", zap.Any("readerConfig", readerConfig), zap.Any("writerConfig", writerConfig))

	dbConnector, err := connector.NewDatabaseConnector(cfg.App.Name, readerConfig, writerConfig)
	if err != nil {
		logger.FatalOutCtx("failed to initialize database connector")
		return nil, err
	}
	
	logger.InfoOutCtx("dbConnector initialized SUCCESSFULLY", zap.Any("dbConnector", dbConnector))
	
	pgConnection := &connector.PgConnection{}
	_, err = pgConnection.NewPool(context.Background(), readerConfig)
	if err != nil {
		logger.FatalOutCtx("failed to create database pool")
		return nil, err
	}
	err = pgConnection.Ping(context.Background())
	if err != nil {
		logger.FatalOutCtx("failed to ping pg connection")
		return nil, err
	}
	
	// Repository initialization
	keyRepository, err := repository.NewKeyRepository(cfg.RSAKeys.PrivateKeyPath, cfg.RSAKeys.PublicKeyPath, cfg.RSAKeys.KID)
	if err != nil {
		logger.FatalOutCtx("failed to initialize key repository")
		return nil, err
	}

	// Service Security initialization
	tokenService := security.NewTokenService()

	// UseCase initialization
	loginUsecase := usecase.NewLoginUseCase(cfg.TokenConfig.TokenTTL, keyRepository, tokenService) 

	// Controller initialization
	authorizerController := controller.NewAuthorizerController(loginUsecase)

	return &Application{
		AuthorizerController: authorizerController,
	}, nil
}
