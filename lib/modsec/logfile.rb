module Modsec
  class Logfile

    # Public: Creates a new logfile object which can be used by Tailers
    #
    # filename - Path to the logfile which should be opened
    # seek - Position in the logfile to seek to
    #
    # Returns an instance of File
    def initialize(filename, seek)
      Modsec::logger.debug("Opening #{filename}, seeking to #{seek}")
      @logfile = _open(filename)
      @directory = File.dirname(filename)
      if seek
        seek(seek)
      end
    end

    # Private: seek to a given position in the logfile
    #
    # pos - Position to seek to
    #
    # Raises a RuntimeError when pos exceeds the file size
    #
    # Returns nothing.
    def seek(pos)
      if pos > @logfile.size
        raise "Seek position (#{pos}) is larger than logfile (#{@logfile.size})"
      end
      @logfile.seek(pos, IO::SEEK_SET)
    end

    # Private: open a logfile
    #
    # Returns an instance of File
    def _open(filename)
      File.open(filename, 'rb')
    end

    private :_open
    attr_reader :logfile, :directory
  end
end