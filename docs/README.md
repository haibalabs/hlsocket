![Ubuntu Build](https://github.com/haibalabs/hlsocket/actions/workflows/ci.yml/badge.svg)

Copyright (c) 2023 Haiba Labs

Author: James Ritts james@haibalabs.com

### Description
-------

This is a cross-platform raw sockets API supporting TLS and WebSockets built upon the Mbed TLS library. It can be compiled on OSX, Windows, Linux, iOS, Android and WASM (via Emscripten).

### Usage
-------

    hlsocketInitializeSSL("server.pem", "server.pem", true);

    HLSocket s = hlsocketCreate(true, false);

    hlsocketConnect(&s, "1.1.1.1", "443", kTCP, 500);
    hlsocketSend(s, "%", 1); // trigger a response 400 from cloudflare

    char buf[1024] = {0};
    hlsocketRecvAllTimeout(s, buf, sizeof(buf), 1000);

    printf("- - - - - - - - - - - - - - - - begin response - - - - - - - - - - - - - - - -\n");
    printf("%s\n", buf);
    printf("- - - - - - - - - - - - - - - -  end response  - - - - - - - - - - - - - - - -\n");

    hlsocketDestroy(&s);

Output:

    - - - - - - - - - - - - - - - - begin response - - - - - - - - - - - - - - - -
    HTTP/1.1 400 Bad Request
    Server: cloudflare
    Date: Tue, 25 Apr 2023 17:19:11 GMT
    Content-Type: text/html
    Content-Length: 155
    Connection: close
    CF-RAY: -

    <html>
    <head><title>400 Bad Request</title></head>
    <body>
    <center><h1>400 Bad Request</h1></center>
    <hr><center>cloudflare</center>
    </body>
    </html>

    - - - - - - - - - - - - - - - -  end response  - - - - - - - - - - - - - - - -

### License
-------

This code licensed under the MIT License, see [LICENSE.txt](https://github.com/haibalabs/hlab_socket/LICENSE.txt) for more information.
