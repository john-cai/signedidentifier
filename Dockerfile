FROM golang:1.10

# Project URI based on repository URL 
ENV PROJECT_URI=github.com/john-cai/keygen
ENV PROJECT_DIR=${GOPATH}/src/${PROJECT_URI}

# Create project directory
RUN mkdir -p ${PROJECT_DIR}

# Change current working directory to project directory
WORKDIR ${PROJECT_DIR}

# Copy source code to project directory
COPY . ${PROJECT_DIR}

# Compile code
RUN go build -o /keygen ${PROJECT_URI}/...
RUN chmod +x /keygen
ENTRYPOINT ["/keygen"]