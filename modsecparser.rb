#!/usr/bin/env ruby

# Add "local" lib dir to $LOAD_PATH if present, allows to run modsecparser from a scm checkout
path = File.dirname(__FILE__) + File.expand_path('/lib')
$LOAD_PATH.unshift(path) if File.directory?(path + '/modsec/')

require 'modsec'
require 'pp'
require 'yaml'
require 'logger'

DEFAULTS = {
    :dry_run => false,
    :config => '/etc/modsecparser.yml',
    :keep_tx => false,
    :logfile => '/var/log/modsecparser.log',
    :loglevel => 'WARN',
    :concurrent_auditlog => '/var/log/modsec_audit.log',
    :concurrent_auditlogdir => '/opt/modsecurity/var/audit/',
    :uri_rewrite => [],
}

BASE_PROGRAM_NAME = File.basename($PROGRAM_NAME)


def parse_options
  require 'optparse'
  options = {}

  OptionParser.new do |opts|
    opts.banner = <<EOS
Usage: #{BASE_PROGRAM_NAME} [options]

#{BASE_PROGRAM_NAME} parses mod_security audit log entries in the concurrent log format and inserts them into
a Postgres database. By default all parsed log and successfully inserted log entries will be deleted.

Most options can also be put in the config file, replace dashes with underscores.
e.g. --keep-tx -> :keep_tx

ARGV options override config file settings

EOS

    opts.on('-v', '--verbose', 'Set loglevel to DEBUG and log to STDOUT') do
      options[:logfile] = 'STDOUT'
      options[:loglevel] = 'DEBUG'
    end

    opts.on('-n', '--dry-run', "Inserts but doesn't commit parsed transactions to database, won't delete transaction files, Default: #{DEFAULTS[:dry_run]}") do |v|
      options[:logfile] = 'STDOUT'
      options[:loglevel] = 'DEBUG'
      options[:dry_run] = v
    end

    opts.on('-k', '--keep-tx', "Don't remove TX files after parsing, Default: #{DEFAULTS[:keep_tx]}") do |v|
      options[:keep_tx] = v
    end

    opts.on('-c', '--config FILE', "Location of config file, Default: #{DEFAULTS[:config]}") do |v|
      options[:config] = v
    end

    opts.on('--logfile FILE', "Where modsecparse should log to, Default: #{DEFAULTS[:logfile]}") do |v|
      options[:logfile] = v
    end

    opts.on('--loglevel LEVEL', "Loglevel to use (DEBUG, INFO, WARN, ERROR), Default: #{DEFAULTS[:loglevel]}") do |v|
      options[:loglevel] = v
    end

    opts.on('--dbuser USER', 'Output database username') do |v|
      options[:dbuser] = v
    end

    opts.on('--dbpassword PASS', 'Output database password') do |v|
      options[:dbpassword] = v
    end

    opts.on('--dbhost HOST', 'Output database host') do |v|
      options[:dbhost] = v
    end

    opts.on('--dbname DBNAME', 'Output database name') do |v|
      options[:dbname] = v
    end

    opts.on('--dbport PORT', 'Output database port') do |v|
      options[:dbport] = v
    end

    opts.on('--auditlog AUDITLOG', "mod_security audit logfile (see SecAuditLog), Default: #{DEFAULTS[:auditlog]}") do |v|
      options[:concurrent_auditlog] = v
    end

    opts.on('--concurrent-auditlogdir AUDITLOGDIR', "mod_security concurrent audit log directory (see SecAuditLogStorageDir), Default: #{DEFAULTS[:concurrent_auditlogdir]}") do |v|
      options[:concurrent_auditlogdir] = v
    end

    opts.on_tail('-h', '--help', 'Show this message') do
      puts opts
      exit
    end

    options[:config] ||= DEFAULTS[:config]
  end.parse!
  options
end

def parse_config(configfile)
  config = {}
  if File.readable?(configfile)
    $logger.debug("Reading config from #{configfile}")
    config = YAML.load_file(configfile)
    config = Hash[config.map{ |k, v| [k.to_sym, v] }]
  else
    $logger.warn("Config file #{configfile} isn't readable")
  end
  config
end

def configure_logger(output, level)
  output = STDOUT if output == 'STDOUT'
  $logger = Logger.new(output)
  $logger.formatter = Modsec::LogFormatter.new
  $logger.level = Logger.const_get(level.upcase.to_sym)
  Modsec::logger = $logger
end

def prepare_dsn(options)
  dsn = {}
  %w(dbuser dbpassword dbhost dbname dbport).each do |k|
    key = (k == 'dbname') ? k : k.sub(/^db/, '')
    if options.key?(k.to_sym)
      dsn[key.to_sym] = options[k.to_sym]
    end
  end
  $logger.debug("Connecting to database with parameters: #{dsn}")
  unless dsn[:dbname]
    $logger.error('You need to specify at least the database name (dbname)')
    exit(1)
  end
  dsn
end


if __FILE__ == $PROGRAM_NAME

  configure_logger(STDOUT, 'WARN')

  options = parse_options
  config = parse_config(options[:config])

  config = DEFAULTS.merge(config)
  options = config.merge(options)

  configure_logger(options[:logfile], options[:loglevel])

  $logger.debug("Combined options: #{options.pretty_inspect}")

  dsn = prepare_dsn(options)

  tailer = Modsec::Tailer.create_tailer(options[:concurrent_auditlog], options[:concurrent_auditlogdir], true)
  writer = Modsec::Writer.new(dsn, options[:uri_rewrite])

  if options[:keep_tx]
    tailer.prune_old_tx = false
    tailer.remove_parsed_tx = false
  end

  $logger.info('Starting to parse transactions')

  txcount = 0

  while tx = tailer.process_next_tx do
    if tx.txid == nil || tx.timestamp == nil
      $logger.info("Failed to parse tx, skipping it: #{tx.pretty_inspect}")
      next
    end
    $logger.debug("Processing tx #{tx.timestamp}: #{tx.txid}")
    writer.write(tx)
    txcount += 1
  end

  # We skip the checkpoint & and pruning cycle if dry_run or keep_tx is activated
  if options[:keep_tx] == false && options[:dry_run] == false
    writer.checkpoint
    tailer.checkpoint
    tailer.prune_txdir
  end

  $logger.info("All done, finishing up - processed #{txcount} tx")

  # We skip closing (and subsequent TX commit/logpos updating) when running in dry_run
  if options[:dry_run]
    $logger.info('Doing a dry run, not saving anything')
  else
    writer.close
    tailer.close
  end
end
