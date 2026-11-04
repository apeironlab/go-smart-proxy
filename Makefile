.PHONY: webui build relay gateway test

webui:
	cd webui && npm run build

build: webui
	go build -o proxy .

test:
	go test -count=1 ./...

# The relay server has no GUI/cgo dependencies: it can be built for any server.
relay:
	CGO_ENABLED=0 go build -o proxyrelay ./cmd/proxyrelay

# The application gateway: run it next to the applications it serves.
gateway:
	CGO_ENABLED=0 go build -o proxygateway ./cmd/proxygateway
