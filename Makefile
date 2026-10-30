.PHONY: webui build relay test

webui:
	cd webui && npm run build

build: webui
	go build -o proxy .

test:
	go test -count=1 ./...

# The relay server has no GUI/cgo dependencies: it can be built for any server.
relay:
	CGO_ENABLED=0 go build -o proxyrelay ./cmd/proxyrelay
