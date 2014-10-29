module Modsec
  class Transaction

    AUDIT_LOG_HEADER_RE = /
^
\[(?<timestamp>[^\]]+)\]
\s
(?<transaction_id>\S+)
\s
(?<source_ip>\S+)
\s
(?<source_port>\d+)
\s
(?<destination_ip>\S+)
\s
(?<destination_port>\d+)
$
/x

    # Taken from https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats#Parts
    # and Ivan Ristic's mod_security handbook
    # mod_security2 comes with a default of SecAuditLogParts configured 'ABIJDEFHZ'
    # nginx logs by default 'ABEFHZ'
    SECTION_NAMES = {
        'A' => :audit_log_header,
        'B' => :request_headers,
        'C' => :request_body,
        'D' => :reserved_D,
        'E' => :response_body,
        'F' => :response_headers,
        'G' => :reserved_G,
        'H' => :audit_log_trailer,
        'I' => :reduced_multipart_request_body,
        'J' => :uploaded_file_information,
        'K' => :matched_rules_information,
        'Z' => :audit_log_footer
    }

    SECTION_NAMES.each_value do |v|
      attr_reader v
    end

    # Response code needs to be set from outside
    attr_accessor :response_code

    attr_reader :timestamp, :txid,
                :source_ip, :source_port, :destination_ip, :destination_port,
                :request_method, :request_uri, :request_host

    # Public: Creates a new instance
    #
    # sections - An array of arrays consisting section identifier and section content pairs
    #
    # Returns an instance of Modsec::Transaction
    def initialize(sections)
      fill_attributes(sections)
    end

    # Private: Initialize instance variables based on transaction content
    #
    # sectionlist - An array of arrays consisting section identifier and section content pairs
    #
    # Returns nothing.
    def fill_attributes(sectionlist)
      sectionlist.each do |section, content|
        instance_variable_set("@#{Modsec::Transaction::SECTION_NAMES[section]}", content)
      end

      # If the audit log header exists in the TX, fill convencien attributes
      if @audit_log_header
        AUDIT_LOG_HEADER_RE.match(@audit_log_header) do |m|
          @timestamp = DateTime.strptime(m[:timestamp], '%d/%b/%Y:%H:%M:%S %z')
          @txid = m[:transaction_id]
          @source_ip = m[:source_ip]
          @source_port = m[:source_port]
          @destination_ip = m[:destination_ip]
          @destination_port = m[:destination_port]
        end

      end

      # If the request headers are logged in the TX, extract interesting fields
      if @request_headers
        @request_method, @request_uri = @request_headers.lines.first.split(/\s+/)[0..1]
        hostmatch = @request_headers.match('^Host:\s+(.*)$')
        @request_host = hostmatch ? hostmatch[1] : nil
      end
    end
  end
end