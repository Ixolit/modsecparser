CREATE TABLE requestlog (
  timestamp         timestamp with time zone NOT NULL,

  request_host      text,
  request_method    text NOT NULL,
  request_uri       bytea NOT NULL,
  response_code     smallint NOT NULL,

  source_ip         inet NOT NULL,
  source_port       integer NOT NULL,
  destination_ip    inet NOT NULL,
  destination_port  integer NOT NULL,

  request_headers   bytea NOT NULL,
  request_body      bytea,

  response_headers  bytea NOT NULL,
  response_body     bytea
);

CREATE INDEX on requestlog(timestamp);
CREATE INDEX on requestlog(request_uri);

CREATE OR REPLACE VIEW requestlog_latin1 AS
    SELECT
      requestlog."timestamp",
      requestlog.request_host,
      requestlog.request_method,
      convert_from(requestlog.request_uri, 'latin1'::name) AS request_uri,
      requestlog.response_code,
      requestlog.source_ip,
      requestlog.source_port,
      requestlog.destination_ip,
      requestlog.destination_port,
      convert_from(requestlog.request_headers, 'latin1'::name) AS request_headers,
      convert_from(requestlog.request_body, 'latin1'::name) AS request_body,
      convert_from(requestlog.response_headers, 'latin1'::name) AS response_headers,
      convert_from(requestlog.response_body, 'latin1'::name) AS response_body
    FROM requestlog;
