FROM golang-glide
COPY . /go/src/app
WORKDIR /go/src/app
RUN glide install
RUN go install -v
CMD ["app"]
