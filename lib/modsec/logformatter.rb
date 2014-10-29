module Modsec
  require 'logger'

  # Custom Formatter for Logger
  class LogFormatter < Logger::Formatter

    # Public: Format a log message
    #
    # See the Logger documentation for details.
    #
    # Returns a formatted log line
    def call(severity, time, progname, msg)
      "[%s#%d] %5s -- %s\n" % [format_datetime(time), Process.pid, severity, msg2str(msg)]
    end
  end
end