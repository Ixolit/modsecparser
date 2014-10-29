module Modsec

  # Mixins for auditlog tailer modules, currently only the concurrent tailer is implemented

  module Tailer

    # Public: Creates a new concurrent auditlog tailer
    #
    # filename - Path to the concurrent index logfile
    # logdir - Path to the concurrent auditlog directory
    # resume - bool that defines if we should consult a resume file for the auditlog
    #
    # Returns an instance of Modsec::Tailer::Concurrent
    def self.create_tailer(filename, logdir=nil, resume=false)
      seek = nil

      if resume
        seek = read_resume_file(filename)
      end

      logfile = Modsec::Logfile.new(filename, seek)

      Modsec::Tailer::Concurrent.new(logfile, logdir)
    end

    # Private: Determine the name of the resume file to use
    #
    # logfile - Path to the logfile
    #
    # Returns an absolute path pointing to the resume file
    def self.resume_file_name(logfile)
      # FIXME - this could be parametrised
      '/var/lib/modsecparser/' + logfile.gsub(/\//, '_')
    end

    # Private: Read & validate the content of the resume file
    #
    # logfilename - Path to the logfile
    #
    # Returns the offset in the auditlog index file that should be used when parsing it
    def self.read_resume_file(logfilename)
      Modsec::logger.debug('Reading resume file')
      rf = resume_file_name(logfilename)
      offset = 0

      if rf && File.exists?(rf)
        inode, offset = File.read(rf).lines.first.split(/\s+/).map{|i| Integer(i)}
        lfstat = File.stat(logfilename)
        Modsec::logger.debug("Resume file states inode: #{inode}, offset: #{offset}, logfile has inode #{lfstat.ino}, size: #{lfstat.size}")

        if inode != lfstat.ino
          Modsec::logger.info("Inodes of log file doesn't match, dropping offset")
          offset = 0
        end

        if lfstat.size < offset
          Modsec::logger.info('Log file is smaller than offset, dropping offset')
          offset = 0
        end

      end
      offset
    end

    # Private: Create or update the resume file with the current position of the logfile
    #
    # logfileobject - The logfile for which the resume file should be created or updated
    #
    # Returns nothing.
    def self.write_resume_file(logfileobject)
      inode = File.stat(logfileobject).ino
      offset = logfileobject.pos
      resume_file = Modsec::Tailer.resume_file_name(logfileobject.path)
      Modsec::logger.debug("Writing resume file #{resume_file}, inode: #{inode}, offset: #{offset}")

      File.open(resume_file, 'w') do |f|
        f.write("#{inode} #{offset}")
      end

    end

  end
end
