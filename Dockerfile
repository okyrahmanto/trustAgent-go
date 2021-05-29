FROM golang:1.16.4-buster
ENV APP_HOME /go/src/github.com/okyrahmanto/chainapplication-go
WORKDIR $APP_HOME
ENV GO111MODULE=on
COPY ./build/agent-things /go/src/github.com/okyrahmanto/chainapplication-go
ENV GOFLAGS=-mod=vendor
ENV APP_USER app
ARG GROUP_ID
ARG USER_ID
RUN useradd -m -l --uid $USER_ID --gid $GROUP_ID $APP_USER
RUN chown -R $APP_USER:$GROUP_ID $APP_HOME
USER $APP_USER
EXPOSE 10000
CMD ["./agent-things"]