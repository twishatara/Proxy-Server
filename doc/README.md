## Proxy Server 

## Short Description
        This proxy server is an advanced HTTP server implemented in C, designed to efficiently manage and process HTTP GET and HEAD requests. It's engineered to support concurrent handling of multiple client requests, leveraging multithreading to ensure high responsiveness and scalability. When a request is received, the server parses it to extract the destination URL, then forwards the request to the corresponding server. Once the response is obtained, it's relayed back to the client. This capability makes it an ideal tool for environments requiring simultaneous connections and data fetching without bottlenecking at the server end.
## Usage
        To start the proxy server, run:
                ./myproxy <port_number>
        To test with Single Requests: 
                For a GET request (on a seprate window): curl -x http://localhost:<port_number> http://example.com
                
                For a HEAD request (on a sperate window): curl -x http://localhost:<port_number> -I http://example.com
        To test with Multiple Requests:
                Use a bash script or similar tool: 
                ## Script ## 
                #!/bin/bash

                # Set the proxy server address and port
                PROXY="http://localhost:<port_number>"

                # URL to request
                URL="http://example.com"

                # Number of requests
                N=10

                for ((i=1; i<=N; i++)); do
                        echo "Request $i"
                        curl -x $PROXY $URL &
                done
                wait
## Features
        HTTP Request Handling: Efficiently supports GET and HEAD methods, allowing for content retrieval and metadata inspection without full content download.
        Concurrent Processing: Utilizes multithreading to handle multiple requests simultaneously, significantly enhancing throughput and server responsiveness.
        URL Parsing: Accurately parses URLs from HTTP requests, ensuring correct destination targeting and forwarding.
        Request Forwarding and Response Relay: Seamlessly forwards requests to the destination server and relays responses back to the client, maintaining transparency and efficiency.