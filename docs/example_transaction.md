### mod_security log format


```
--4ae37c48-A--
[03/Nov/2014:13:12:06 +0100] VFdxFn8AAAEAAAv2AaMAAABF 192.168.54.1 63015 192.168.54.130 80
--4ae37c48-B--
GET / HTTP/1.1
Host: modsec.local
Connection: keep-alive
Pragma: no-cache
Cache-Control: no-cache
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.42 Safari/537.36
DNT: 1
Accept-Encoding: gzip, deflate, sdch
Accept-Language: en-US,en;q=0.8,de;q=0.6

--4ae37c48-F--
HTTP/1.1 200 OK
Last-Modified: Wed, 25 Jun 2014 17:48:29 GMT
ETag: "a083b-b1-4fcacaf188d3d"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 146
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

--4ae37c48-E--
<html><body><h1>It works!</h1>
<p>This is the default web page for this server.</p>
<p>The web server software is running but no content has been added, yet.</p>
</body></html>

--4ae37c48-H--
Stopwatch: 1415016726849471 1793 (- - -)
Stopwatch2: 1415016726849471 1793; combined=585, p1=37, p2=447, p3=4, p4=4, p5=93, sr=0, sw=0, l=0, gc=0
Response-Body-Transformed: Dechunked
Producer: ModSecurity for Apache/2.6.6 (http://www.modsecurity.org/).
Server: Apache/2.2.22 (Debian)

--4ae37c48-Z--
```

### modsecparser database schema

```
requestlog=# select * from requestlog_latin1;
-[ RECORD 1 ]----+-------------------------------------------------------------------------------------------------------------------------------------
timestamp        | 2014-11-03 13:12:06+01
request_host     | modsec.local
request_method   | GET
request_uri      | /
response_code    | 200
source_ip        | 192.168.54.1
source_port      | 63015
destination_ip   | 192.168.54.130
destination_port | 80
request_headers  | GET / HTTP/1.1
                 | Host: modsec.local
                 | Connection: keep-alive
                 | Pragma: no-cache
                 | Cache-Control: no-cache
                 | Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
                 | User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.42 Safari/537.36
                 | DNT: 1
                 | Accept-Encoding: gzip, deflate, sdch
                 | Accept-Language: en-US,en;q=0.8,de;q=0.6
                 | 
request_body     | 
response_headers | HTTP/1.1 200 OK
                 | Last-Modified: Wed, 25 Jun 2014 17:48:29 GMT
                 | ETag: "a083b-b1-4fcacaf188d3d"
                 | Accept-Ranges: bytes
                 | Vary: Accept-Encoding
                 | Content-Encoding: gzip
                 | Content-Length: 146
                 | Keep-Alive: timeout=5, max=100
                 | Connection: Keep-Alive
                 | Content-Type: text/html
                 | 
response_body    | <html><body><h1>It works!</h1>
                 | <p>This is the default web page for this server.</p>
                 | <p>The web server software is running but no content has been added, yet.</p>
                 | </body></html>
                 | 
```