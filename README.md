
# Project: dynip-client

Project dynip-client is an example java program to demonstrate the use of asymmetric RSA keys.

This program works in concert with dynip-server, dynip-query.

You can use a browser to query dynip-server as follows: 

Set host, port and protocol as appropriate.
    
        <protocol>://<hostname>:<port>/ipserver/server/ip/query
    
e.g.
    
        https://localhost/ipserver/server/ip/query

or

        http://localhost:8080/ipserver/server/ip/query
     
## Usage

1. Pre-requisites:

    Software:
    
    ```text
    Java 1.9.  
    Gradle 8.0.2.   
    Openssl 3.0.2.
    Linux (Ubuntu 22.04.2 LTS (Jammy Jellyfish)).
    ```
    
    Environment:
    
    ```text
    $projectDir must be correctly set - watch for spaces !!!
    ```
    
2. Build:

    Navigate to project home directory and execute the following commands

    ```bash
    cd $projectDir
    ./gradlew clean
    ./gradlew build
    ./gradlew javadoc
    ```
    The build creates a jar located at $projectDir/build/libs/dynip-client.jar

3. Run:

    3.1 Example 1
    
    ```bash
    cd $projectDir/build/libs
    java -jar dynip-client.jar -h
    ```
    output:
    
    ```text
    Fri Mar 17 01:26:23 EDT 2023: running
    usage:
    java -jar dynip-client.jar [-protocol (http|https)] -hostname (ip|domain) [-port <port>] 
        [-uri <path>] -client-private-key <file> -client-public-key <file> 
        -server-public-key <file> -credentials <file> [-debug]
    
    -protocol:           optional.  set to http or https. default https.
    -hostname:           mandatory. server host. can be an ip address or name.
    -port:               optional.  server port. default 80/443 based on protocol.
    -uri:                optional.  url server endpoint prefix. default '/ipserver/server/ip'.
    -client-private-key: mandatory. client's private key file.
    -client-public-key:  mandatory. client's public key file.
    -server-public-key:  mandatory. server's public key file.
    -credentials:        mandatory. credentials for server access.
    -debug:              optional.  toggle to adjust debug mode. default false.
    ```
    
    3.ii Example 2
    
    ```bash
    cd $projectDir/build/libs
    java -jar dynip-client.jar -hostname www.server.com -protocol https \
        -client-private-key $projectDir/src/main/sh/client/client-private.key \
        -client-public-key $projectDir/src/main/sh/client/client-public.key \
        -server-public-key $projectDir/src/main/sh/server/server-public.key \
        -credentials ../../src/main/sh/server/credentials -debug
    ```
        
    output:
    
    ```text
    Fri Mar 17 01:34:07 EDT 2023: running
    Fri Mar 17 01:34:07 EDT 2023: configuration
    -protocol:           https
    -hostname:           www.server.com
    -port:               443
    -uri:                /ipserver/server/ip
    -client-private-key: ../../src/main/sh/client/client-private.key
    -client-public-key:  ../../src/main/sh/client/client-public.key
    -server-public-key:  ../../src/main/sh/server/server-public.key
    -credentials:        ../../src/main/sh/server/credentials
    -debug:              true
    fini.
    ```

## Credentials

1. Credentials File:

    The credentials file is specified using program parameter -credentials.

    The credentials file has the following format:
    
    ```text
    <user-id>
    <user-password>
    ```
    
    The credentials file must be encrypted before it can be used with this client. 

    The following bash commands can be used to encrypt and decrypt the file

    Decrypt:

    ```bash
    base64 -d credentials.encrypted | \
        openssl pkeyutl -decrypt -inkey $projectDir/src/main/sh/client/client-private.key \
        -keyform PEM -pkeyopt rsa_padding_mode:pkcs1 
    ```
    
    Encrypt:
    
    ```bash
    openssl pkeyutl -encrypt -pubin -inkey $projectDir/src/main/sh/client/client-public.key \ 
        -in credentials.plaintext -keyform PEM -pkeyopt rsa_padding_mode:pkcs1 | \
        base64 | tr -d "\n" > credentials.encrypted
    ```
    
## Asymmetric Keys

1. Key Generation

    The following commands are used to generate private and public keys.
    
    Server:
    
    ```bash
    openssl genpkey -out server-private.key -algorithm RSA -pkeyopt rsa_keygen_bits:4096
    openssl rsa -pubout -outform pem -in server-private.key -out server-public.key
    ```
    
    The server private key "server-private.key" should be configured in the dynip-server inatance for this client.
    
    Client:
    
    ```bash
    openssl genpkey -out client-private.key -algorithm RSA -pkeyopt rsa_keygen_bits:4096
    openssl rsa -pubout -outform pem -in client-private.key -out client-public.key 
    ```

