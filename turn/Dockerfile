# -------- build stage --------
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /turn .

# -------- runtime stage --------
FROM scratch
COPY --from=build /turn /turn
EXPOSE 3478/udp
ENTRYPOINT ["/turn"]
