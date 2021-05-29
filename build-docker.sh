GOOS=linux GOARCH=amd64 go build -o build/agent-things .
docker build \                                               
         --build-arg USER_ID=$(id -u) \
         --build-arg GROUP_ID=$(id -g) \
         -t chainapplication-go .
#docker run -it --rm -p 10000:10000 chainapplication-go:latest 
