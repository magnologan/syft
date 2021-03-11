FROM alpine:latest AS build

RUN apk --no-cache add ca-certificates

FROM scratch
# needed for version check HTTPS request
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY dist/syft_linux_amd64/syft /

# create the /tmp dir, which is needed for image content cache
WORKDIR /tmp

ENTRYPOINT ["/syft"]