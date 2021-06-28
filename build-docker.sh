OS=`uname -s`
if  [ $OS == "Darwin" ]; then
    OS='linux'
    ARCHITECTURE='amd64'
else 
    OS='linux'
    ARCHITECTURE=`dpkg --print-architecture`
fi
GOOS=$OS GOARCH=$ARCHITECTURE go build -o build/agent-things .
docker build --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) --no-cache -t agent-things .
if [ ! -z "$1" ]; then    
    docker run -it --rm -p $1:10000 --network="first-network" --network="node" agent-things:latest 
fi

