include .env
export

.PHONY: help
help: ## display this help screen
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: op
op: ## Run op.
	@go run ./example/server/main.go

.PHONY: rp
rp: ## Run rp
	@CLIENT_ID=web CLIENT_SECRET=secret ISSUER=http://localhost:8888 SCOPES="openid profile" PORT=9999 go run example/client/app/app.go
