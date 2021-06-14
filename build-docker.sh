OS=`uname -s`
if  [ $OS == "Darwin" ]; then
    OS='linux'
    ARCHITECTURE='amd64'
else 
    OS='linux'
    ARCHITECTURE=`dpkg --print-architecture`
fi
GOOS=$OS GOARCH=$ARCHITECTURE go build -o build/agent-things .
docker build --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) -t agent-things .
#docker run -it --rm -p 10000:10000 chainapplication-go:latest 
