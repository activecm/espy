# Build container
FROM golang:1.17-alpine as espy-build

RUN apk add --no-cache git make ca-certificates wget build-base

# copy the code in
WORKDIR /go/src/github.com/activecm/espy
COPY . ./

WORKDIR ./espy
RUN go mod download

# Change ARGs with --build-arg to target other architectures
# Produce a self-contained statically linked binary
ARG CGO_ENABLED=0
# Set the build target architecture and OS
ARG GOARCH=amd64
ARG GOOS=linux
# Passing arguments in to make result in them being set as
# environment variables for the call to go build
RUN make CGO_ENABLED=$CGO_ENABLED GOARCH=$GOARCH GOOS=$GOOS

FROM debian:stretch-slim
WORKDIR /
COPY --from=espy-build /go/src/github.com/activecm/espy/espy/etc/espy.yaml /etc/espy/config.yaml
COPY --from=espy-build /go/src/github.com/activecm/espy/espy/espy /espy

ENTRYPOINT ["/espy"]
