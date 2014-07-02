#!/usr/bin/ruby
require 'parslet'
require 'pp'
require 'colorize'

class Str < Parslet::Parser
	rule(:s)       { match('\s').repeat 1                                                                                                 }
	rule(:short)   { str('short').as(:short)                                                                                              }
	rule(:long)    { str('long').as(:long)                                                                                                }
	rule(:binary)  { str('unsigned char*').as(:binary)                                                                                    }
	rule(:type)    { short | long | binary                                                                                                }
	rule(:name)    { match('[a-zA-Z_]') >> match('[a-zA-Z0-9_]').repeat                                                                   }
	rule(:comment) { str '///'                                                                                                            }
	rule(:opts)    { comment >> str('~rsa').as(:opt)                                                                                      }
	rule(:inline)  { s.maybe >> type.as(:type) >> s >> name.as(:var) >> s.maybe >> str(';') >> s.maybe >> opts.maybe.as(:opts) >> s.maybe }
	rule(:header)  { str('typedef') >> s >> str('struct') >> s >> name.as(:hpkt) >> s.maybe >> str('{') >> s.maybe                        }
	rule(:footer)  { s.maybe >> str('}') >> s.maybe >> name.as(:fpkt) >> s.maybe >> str(';')                                              }
	rule(:code)    { s.maybe >> header >> inline.repeat(1).as(:inline) >> footer >> s.maybe                                               }
	root :code
end

def parse(str)
	uct = Str.new
	uct.parse str
rescue Parslet::ParseFailed => failure
	puts "#{failure.cause.ascii_tree}".red
	exit 1
end

def ppp(i, str)
	print "#{"\t" * i}#{str}\n"
end

def typesize
	{
		:short => 2,
		:long => 4
	}
end

def typeconv
	{
		:short => "stoc",
		:long => "ltoc"
	}
end

def gen_strtopkt(pkt)
	i = 0
	ppp i, "rotmg_packet*"
	ppp i, "rotmg_strtopkt_#{pkt[:hpkt].to_s} (#{pkt[:hpkt].to_s}* str) {"
	i += 1
	pkt[:inline].each do |line|
		type = line[:type].first[0]
		# prepare shorts/longs
		if [:short, :long].include? type
			ppp i, "//#{line[:var].to_s.tr '_', ' '}"

			ppp i, ["unsigned char*",
					"temp_#{line[:var].to_s}", "=",
					"#{typeconv[type]}",
					"(str->#{line[:var].to_s})"].join(' ') + ";"

			ppp i, ["unsigned char*",
					"#{line[:var].to_s}", "=",
					"reverse_endian(#{typesize[type]},",
					"temp_#{line[:var].to_s})"].join(' ') + ";"

			ppp i, "free(temp_#{line[:var].to_s});"
		elsif line[:opts] && line[:opts][0][:opt] == "rsa"
			# encrypt using rsa
		end
	end
	i = 0
	ppp i, '}'
end

def analyze(pkt)
	res = []
	
	if pkt[:hpkt].to_s != pkt[:fpkt].to_s
		res << "Struct names do not match:".red
		res << "\ttypedef struct #{pkt[:hpkt].to_s.red} {"
		res << "\t\t[...]"
		res << "\t} #{pkt[:fpkt].to_s.red};"
	end

	binaries = 0
	lengths = 0
	pkt[:inline].each do |line|
		type = line[:type].first[0]
		if type == :binary
			binaries += 1
		elsif type == :short and line[:var].to_s.end_with? '_length'
			lengths += 1
		end
	end

	if binaries != lengths
		res << binaries > lengths ? "#{binaries - lengths} binary field(s) length missing".red : "#{lengths - binaries} unused length fields".yellow
	end

	return res.join "\n"
end

str = parse ARGF.read
ana = analyze str
if ana.length > 0
	puts ana
else
	gen_strtopkt str
end
