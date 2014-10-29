module Modsec
  module Tailer
    require 'date'

    # A tailer for concurrent mod_security auditlogs

    class Concurrent
      include Modsec::Tailer
      attr_reader :logfile
      attr_accessor :prune_old_tx, :remove_parsed_tx

      # Maximum allowed age for TX files during prune
      MAX_TX_PRUNE_AGE = 24 * 3600
      # Maximum allowed age for empty directories during prune
      MAX_EMPTY_TXDIR_PRUNE_AGE = 60 * 10

      TX_FILE_RE = /^\d{8}-\d{6}-[[:ascii:]]{24}$/


      # Pubblic: Create a new concurrent auditlog tailer
      #
      # logfile - The concurrent auditlog index file
      # txlogdir - The concurrent auditlog log directory
      #
      # Returns the instance
      def initialize(logfile, txlogdir)
        @logfile = logfile.logfile
        @txlogdir = Dir.new(txlogdir)
        @processed_tx_files = []
        @remove_parsed_tx = true
        @prune_old_tx = true
        Modsec::logger.debug 'created a new concurrent tailer'
      end

      # Public: Parse all transactions from the auditlog index file
      #
      # Returns an array containing Modsec::Transaction objects
      def process_all_tx
        result = []
        while tx = process_next_tx
          result.push(tx)
        end
        result
      end

      # Public: Parse the next transaction from the auditlog index file
      #
      # Returns an instance of Modsec::Transaction or nil if EOF is reached
      def process_next_tx
        begin
          tx = nil
          until tx do
            tx = process_tx(@logfile.readline)
          end
        rescue EOFError
          return nil
        end
        tx
      end

      # Private: process a single line of the concurrent auditlog
      #
      # line - A line from the concurrent auditlog index file
      #
      # This will parse the line, open the respective concurrent auditlog TX file, parse the file
      # and return a Transaction object
      #
      # Returns an instance of Modsec::Transaction
      def process_tx(line)
        txoverview = Modsec::Parser::parse_concurrent_log_entry(line)

        unless txoverview
          Modsec::logger.warn("Couldn't parse tx concurrent log line: '#{line}'")
          return nil
        end

        txfile = @txlogdir.path + txoverview[:transaction_file]

        unless File.exists?(txfile)
          Modsec::logger.warn("Couldn't parse transaction, tx file #{txfile} didn't exist")
          return nil
        end

        txlog = File.binread(txfile)
        txcontent = Modsec::Parser::parse_transaction(txlog)

        unless txcontent
          Modsec::logger.warn("Couldn't parse transaction #{txfile}")
          return nil
        end

        @processed_tx_files.push(txfile)

        # FIXME - mod_security for nginx
        # HTTP response headers don't contain the response code?!
        txcontent.response_code = txoverview[:response_code]
        txcontent
      end

      # Private: Clean up concurrent auditlog directory
      #
      # This method will remove stale files and directories from the auditlog transaction directory
      #
      # Raises a RuntimeError when the path looks unsafe.
      #
      # Returns nothing
      def prune_txdir
        unless @prune_old_tx
          Modsec::logger.debug('Not pruning old TX, disabled in instance')
          return
        end

        if @txlogdir.path.empty? || @txlogdir.path == '/'
          Modsec::logger.error 'txlogdir looks strange, not going to prune'
          # FIXME Needs a nicer Raise message
          raise 'Strange txlogdir'
        end

        Dir[@txlogdir.path + '/**/*'].reverse.each do |e|
          if File.file?(e) &&
              (Time.now - File.mtime(e)) > MAX_TX_PRUNE_AGE &&
              TX_FILE_RE =~ File.basename(e)
            Modsec::logger.info "Pruning stale TX file #{e}"
            File.unlink(e)
            next
          end

          if File.directory?(e)
            if (Dir.entries(e) - %w[ . .. ]).empty? &&
                (Time.now - File.mtime(e)) > MAX_EMPTY_TXDIR_PRUNE_AGE
              Modsec::logger.debug "Pruning empty directory #{e}"
              Dir.unlink(e)
            end
          end
        end
      end

      # Public: Persist progress of the tailer
      #
      # Removes all succesfully parsed auditlog transaction files and record position of the auditlog index file
      #
      # Returns nothing.
      def checkpoint
        remove_processed_tx_files
        Modsec::Tailer.write_resume_file(@logfile)
      end


      # Private: Remove all successfully parsed transaction files
      #
      # Returns nothing.
      def remove_processed_tx_files
        unless @remove_parsed_tx
          Modsec::logger.debug('Not removing processed TX, disabled in instance')
          return
        end
        @processed_tx_files.each do |txfile|
          Modsec::logger.debug("Removing #{txfile}")
          File.unlink(txfile)
        end
        @processed_tx_files = []
      end

      # Public: Close the tailer
      #
      # Does a checkpoint of the tailer state and closes the auditlog index logfile.
      #
      # Returns nothing.
      def close
        checkpoint
        @logfile.close
      end

    end
  end
end