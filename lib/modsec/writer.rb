module Modsec
  class Writer
    require 'pg'

    # Public: Create a new Writer
    #
    # dsn - The data source name of the database to connect to
    # uriregex - An array of regexp and replacement string pairs
    #
    # Returns a Modsec::Writer instance
    def initialize(dsn, uriregex)
      @db = connect_db(dsn)
      @uriregex = uriregex.map { |m, r| [Regexp.new(m), r] }
    end


    # Public: Write a transaction
    #
    # tx - an instance of Modsec::Transaction
    #
    # Writes the tx to the database, opens a new database transaction if necessary.
    # If the tx can't be inserted, skips the tx.
    #
    # Returns nothing.
    def write(tx)
      if @db.transaction_status != PGconn::PQTRANS_INTRANS
        Modsec::logger.debug('Starting new database transaction')
        @db.exec('BEGIN')
        # Initialize SAVEPOINT in case the first write should fail
        @db.exec('SAVEPOINT SP')
      end

      uri = transform_uri(tx.request_uri)

      # Ruby PG needs handholding when inserting non-utf8 string-like data.
      # If it's a string not containing a number, we send it as binary, otherwise plain
      values = [
          {:value => tx.timestamp, :format => 0},
          {:value => tx.request_host, :format => 0},
          {:value => tx.request_method, :format => 0},
          {:value => uri, :format => 1},
          {:value => tx.response_code, :format =>0},
          {:value => tx.source_ip, :format => 0},
          {:value => tx.source_port, :format => 0},
          {:value => tx.destination_ip, :format => 0},
          {:value => tx.destination_port, :format => 0},
          {:value => tx.request_headers, :format => 1},
          {:value => tx.request_body, :format => 1},
          {:value => tx.response_headers, :format => 1},
          {:value => tx.response_body, :format => 1}
      ]

      begin
        @db.exec_prepared('insert_tx', values)
        @db.exec('SAVEPOINT SP')
      # Trying to catch issues with broken transactions causing data type errors
      rescue Exception => e
        Modsec::logger.warn("Error while writing to database: #{e.message}, skipping transaction")
        Modsec::logger.warn("TX values: #{values.pretty_inspect}")
        # If there are issues with the database handle itself, this will raise again
        @db.exec('ROLLBACK TO SP')
      end

    end

    # Public: Persist data written up to this point
    #
    # Returns nothing
    def checkpoint
      if @db.transaction_status == PGconn::PQTRANS_INTRANS
        Modsec::logger.debug('Commiting')
        @db.exec('COMMIT')
      end
    end

    # Public: Connect to a database
    #
    # dsn - The data source name of the database to connect to
    #
    # Returns an instance of PGconn
    def connect_db(dsn)
      conn = PGconn.open(dsn)
      stmt = <<EOS
          INSERT INTO requestlog(
            timestamp, request_host, request_method, request_uri, response_code,
            source_ip, source_port, destination_ip, destination_port,
            request_headers, request_body, response_headers, response_body
          )
          VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
EOS
      conn.prepare('insert_tx', stmt)
      conn
    end

    # Private: Transform URI prior to writing it to the database
    #
    # uri - An URI
    #
    # The URI will be
    #  * matched against all uriregexes passed to the initializer of the Modsec::Writer object
    #  * the first matching regex plus replace pattern will be passed to gsub
    #  * after that the URI will be truncated to 2048 characters if necessary
    #
    #
    # Returns the transformed URI
    def transform_uri(uri)
      Modsec::logger.debug("Transforming URI #{uri}")

      uri_transformed = uri

      @uriregex.each { |search, replace|
        Modsec::logger.debug("Testing regex #{search}")
        if uri.match(search)
          Modsec::logger.debug("Rewriting URI '#{uri}', match: #{search}, replace: #{replace}")
          uri_transformed = uri.gsub(search, replace)
          Modsec::logger.debug("Rewritten URI to '#{uri_transformed}'")
          break
        end
      }
      # limit request_uri to 2kb to prevent database indexing problems
      uri_transformed[0, 2048]
    end

    # Public: Persist written data and close the database connection
    #
    # Returns nothing.
    def close
      checkpoint
      @db.finish
    end

  end
end