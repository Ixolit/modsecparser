module Modsec
  module Parser

    CONCURRENT_LOG_ENTRY_REGEX = Regexp.new(/
^
(?:
  (?<request_host>\S+) # May be empty on nginx
)?
\s
(?<remote_ip>\S+)
\s
(?<remote_user>\S+)
\s+
(?:
  (?<ident>[^\[]+)     # May be empty on nginx
  \s
)?
\[(?<timestamp>[^\]]+)\]
\s
"(?<request>(?:[^"\\]|\\.)+)"  # We need to handle escaped quote characters
\s
(?<response_code>\d+)
\s
(?<response_body_size>\d+)
\s
"(?<referer>[^"]+)"
\s
"(?<user_agent>[^"]+)"
\s
(?<transaction_id>\S+)
\s
"(?<session_id>[^"]+)"
\s
(?<transaction_file>\S+)
\s
(?<transaction_file_offset>\d+)
\s
(?<transaction_size>\d+)
\s
(?<transaction_checksum>\S+)
\s*
L?                    # Reduced Line Marker
$
/x)

    # Public: Parse a concurrent auditlog transaction
    #
    # tx - the content of the transaction to parse
    #
    # Raises a RuntimeError when it encounters a parse error
    #
    # Returns an instance of Modsec::Transaction with the content of the transaction
    def self.parse_transaction(tx)

      lines = tx.split(/\n/)

      startboundary, startsection = extract_tx_section_header(lines[0])
      endboundary, endsection = extract_tx_section_header(lines[-1])

      unless startboundary
        raise "Couldn't find header in first line of TX"
      end

      unless startsection == 'A'
        raise "First section was #{startsection}, expected A"
      end

      unless endboundary
        raise "Couldn't find header in last line of TX"
      end

      unless endsection == 'Z'
        raise "Last section was #{endsection}, expected Z"
      end

      unless startboundary == endboundary
        raise "Boundary mismatch: start #{startboundary}, end: #{endboundary}"
      end

      sections = extract_tx_sections(tx, startboundary)
      Modsec::Transaction.new(sections)
    end

    # Public: Parses a concurrent auditlog index file entry
    #
    # line - A line from a concurrent auditlog index file
    #
    # Returns an instance of MatchData or nil when the line can't be parsed
    def self.parse_concurrent_log_entry(line)
      matchgroups = line.match(CONCURRENT_LOG_ENTRY_REGEX)

      unless matchgroups
        Modsec::logger.debug("Concurrent log regex didn't match for line #{line}")
        return nil
      end

      matchgroups
    end

    # Private: Extract the section header of an auditlog transaction
    #
    # line - The first line of an auditlog transaction
    #
    # Returns two strings
    #   boundary - the boundary string for the transaction
    #   section - the section identifier, usually A indicating the auditlog tx header
    #   OR
    #   nil - The transaction header couldn' be parsed
    def self.extract_tx_section_header(line)
      boundary, section = /--([a-z0-9]+)-([A-Z])--/.match(line).captures
      unless boundary && section
        return nil
      end
      return boundary, section
    end

    # Private: Parses the auditlog transaction and extracts all sections
    #
    # tx - the auditlog transaction
    # boundary - the boundary identifier for the transaction
    #
    # Raises a RuntimeError on parse errors
    #
    # Returns an Array of Arrays consisting of section identifier and section content
    def self.extract_tx_sections(tx, boundary)
      regex = /
(?:
  --                            # Match section header start
  #{boundary}
  -
  ([A-Z])
  --\n                          # Match section header end
  (
    (?:
      \n?                       # Match an optional newline (right after a section header we don' see a newline)
      (?!--#{boundary}-[A-Z]--) # Negative lookahead: Make sure we're not about to parse a section header
      [^\n]*                    # Match all characters up to the next newline
    )+                          # Match as many lines as possible
  )
)+                              # Match as many section headers as possible
/mx

      r = Regexp.new(regex)

      sections = tx.scan(r)
      if sections.empty?
        raise "Couldn't find sections"
      end

      sections
    end

  end
end