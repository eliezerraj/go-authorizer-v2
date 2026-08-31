package repository

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/eliezerraj/go-core/v3/logger"
	"github.com/eliezerraj/go-core/v3/database/connector"

	"github.com/go-authorizer-v2/application/tracing"
	"github.com/go-authorizer-v2/application/domain/entity"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/codes"
)

type ClientRepository struct{
	dbConnector connector.IDatabaseConnector
}

type IClientRepository interface {
	ClientGet(ctx context.Context, client entity.Client) (*entity.Client, error)
}

func NewClientRepository(dbConnector connector.IDatabaseConnector) IClientRepository {
	return &ClientRepository{
		dbConnector: dbConnector,
	}
}

func (r *ClientRepository) ClientGet(ctx context.Context, client entity.Client) (res_client *entity.Client, err error) {
	logger.Info(ctx, "client repository ClientGet called")

	// Tracing and metrics
	ctx, span := tracing.CustomStartSpanCtx(ctx, "clientRepository.ClientGet", trace.SpanKindInternal)
	defer span.End()

	meter := otel.Meter("go-authorizer-v2.repository")
    counter, _ := meter.Int64Counter("db_custom_client_get_requests_total")
    histogram, _ := meter.Float64Histogram("db_custom_client_get_duration_seconds")
    start := time.Now()

    counter.Add(ctx, 1, metric.WithAttributes(
        attribute.String("operation", "ClientGet"),
    ))
	
	defer func() {
		if err != nil {
			span.RecordError(err) 
			span.SetStatus(codes.Error, err.Error())
			logger.Error(ctx, "client repository ClientGet failed", zap.Error(err))
		}
        histogram.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(
            attribute.String("operation", "ClientGet"),
        ))
	}()

	connectorReader := r.dbConnector.Reader()

	query := `SELECT id, 
					name
			FROM clients WHERE id = ?`

	var cli entity.Client
	err = connectorReader.QueryRow(ctx, query, client.ID).Scan(&cli.ID, &cli.Name)
	if err != nil {
		return nil, err
	}
	return &cli, nil
}