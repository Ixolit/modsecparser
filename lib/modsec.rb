require 'modsec/parser'
require 'modsec/logfile'
require 'modsec/tailer'
require 'modsec/tailer/concurrent'
require 'modsec/transaction'
require 'modsec/writer'
require 'modsec/logformatter'
require 'logger'


module Modsec

  VERSION = '0.1.1'

  def self.logger
    unless @logger
      @logger = Logger.new('/dev/null')
      @logger.level = Logger::Severity::UNKNOWN
    end
    @logger
  end

  def self.logger=(logger)
    @logger = logger
  end
end
