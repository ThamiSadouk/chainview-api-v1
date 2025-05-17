include .env
DB_URL ?= postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable

# Run all migrations
migrate-up:
	docker run --rm \
		--network chainview-api-v1_default \
		-v $(PWD)/migrations:/migrations \
		migrate/migrate \
		-path=/migrations \
		-database "$(DB_URL)" \
		up

# Rollback the last migration
migrate-down:
	docker run --rm \
	--network chainview-api-v1_default \
	-v $(PWD)/migrations:/migrations \
	migrate/migrate \
	-path=/migrations \
	-database "$(DB_URL)" \
	down 1

# Rollback everything
migrate-drop:
	docker run --rm \
	--network chainview-api-v1_default \
	-v $(PWD)/migrations:/migrations \
	migrate/migrate \
	-path=/migrations \
	-database "$(DB_URL)" \
	drop -f

# Check migration status
migrate-status:
	docker run --rm \
	--network chainview-api-v1_default \
	-v $(PWD)/migrations:/migrations \
	migrate/migrate \
	-path=/migrations \
	-database "$(DB_URL)" \
	version

# Drop everything and rerun from scratch (use with caution)
#migrate-force:
#	migrate -path migrations -database "$(DB_URL)" drop -f && migrate -path migrations -database "$(DB_URL)" up

# Create a new migration file
# Usage: make migrate-new name=create_users_table
#migrate-new:
#	migrate create -ext sql -dir migrations -seq $(name)


# Help
help:
	@echo "Available commands:"
	@echo "  make migrate-up       # Run all up migrations"
	@echo "  make migrate-down     # Rollback last migration"
	@echo "  make migrate-force    # Drop and re-run all migrations"
	@echo "  make migrate-new name=add_users_table"